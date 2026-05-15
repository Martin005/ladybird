/*
 * Copyright (c) 2026-present, the Ladybird developers.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

use chardetng::{EncodingDetector, Iso2022JpDetection, Utf8Detection};

/// Attempts to detect the character encoding of a byte stream using frequency analysis.
///
/// This implements step 8 of the WHATWG encoding sniffing algorithm:
/// https://html.spec.whatwg.org/multipage/parsing.html#determining-the-character-encoding
///
/// # Safety
/// - `input` and `input_len` must describe a valid byte slice (or `input` may be null if
///   `input_len` is 0)
/// - `tld` if non-null, must describe a valid byte slice of `tld_len` bytes containing the
///   rightmost DNS label of the resource's host, with no dots, no uppercase, and only ASCII
///   characters — these constraints are required by chardetng and must be validated by the caller
/// - `out_encoding_name` and `out_encoding_name_len` must be non-null writable pointers
///
/// Returns `true` if an encoding was detected (always, unless the input pointer is invalid).
/// When `true` is returned, `*out_encoding_name` is set to a pointer into a static ASCII
/// string naming the detected encoding (e.g. `"windows-1252"`, `"Shift_JIS"`), and
/// `*out_encoding_name_len` is set to its byte length. The pointer is valid for the lifetime
/// of the process. When `false` is returned (only on null-pointer error), the output pointers
/// are left unmodified.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_detect_encoding(
    input: *const u8,
    input_len: usize,
    tld: *const u8,
    tld_len: usize,
    out_encoding_name: *mut *const u8,
    out_encoding_name_len: *mut usize,
) -> bool {
    unsafe {
        crate::abort_on_panic(|| {
            let Some(input_slice) = crate::bytes_from_raw(input, input_len) else {
                return false;
            };

            let tld_slice = if tld.is_null() || tld_len == 0 {
                None
            } else {
                Some(std::slice::from_raw_parts(tld, tld_len))
            };

            // Web browsers must use Iso2022JpDetection::Deny and Utf8Detection::Deny to
            // prevent charset confusion attacks. See the chardetng documentation for details.
            // Japanese pages using ISO-2022-JP will have declared it in a <meta> tag, which
            // is detected in step 5 (prescan) before this step is reached.
            // We always call guess() even for pure-ASCII input because chardetng still
            // tracks ESC sequences (ISO-2022-JP uses 7-bit escapes) and returns the
            // correct locale-based fallback (windows-1252 for generic TLD) with
            // Utf8Detection::Deny when no distinctive non-ASCII encoding evidence is found.
            let mut detector = EncodingDetector::new(Iso2022JpDetection::Deny);
            // Pass last=false because the caller may only be providing a sniff-bytes prefix
            // of a longer stream. chardetng docs: "If you want to perform detection on just
            // the prefix of a longer stream, do not pass last=true."
            detector.feed(input_slice, false);

            // Utf8Detection::Deny: chardetng never returns UTF-8 here; valid-UTF-8
            // content (including pure ASCII) gets the TLD-based default (windows-1252
            // for generic), while content in a non-UTF-8 encoding gets that encoding.
            let encoding = detector.guess(tld_slice, Utf8Detection::Deny);
            let name = encoding.name().as_bytes();
            *out_encoding_name = name.as_ptr();
            *out_encoding_name_len = name.len();
            true
        })
    }
}

/// Opaque handle to a streaming `EncodingDetector` for incremental byte-by-byte detection.
///
/// Created with `rust_encoding_detector_new`, fed incrementally with
/// `rust_encoding_detector_feed`, queried with `rust_encoding_detector_guess`, and
/// destroyed with `rust_encoding_detector_free`. The caller must not use the handle after
/// calling `rust_encoding_detector_free`.
pub struct OpaqueEncodingDetector {
    detector: EncodingDetector,
    /// Set to `true` once `feed` has been called with `last = true`; further `feed` calls
    /// after this point are silently ignored (chardetng would panic otherwise).
    finished: bool,
}

/// Create a new streaming encoding detector.
///
/// Returns a heap-allocated `OpaqueEncodingDetector` that must be freed with
/// `rust_encoding_detector_free`. Never returns null.
///
/// # Safety
/// The returned pointer must be passed only to `rust_encoding_detector_feed`,
/// `rust_encoding_detector_guess`, and `rust_encoding_detector_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_encoding_detector_new() -> *mut OpaqueEncodingDetector {
    Box::into_raw(Box::new(OpaqueEncodingDetector {
        detector: EncodingDetector::new(Iso2022JpDetection::Deny),
        finished: false,
    }))
}

/// Feed a chunk of bytes into the streaming detector.
///
/// The byte stream is represented as a sequence of calls; the concatenation of all `buffer`
/// arguments forms the complete stream being analyzed. Pass `last = true` on the final chunk
/// (which may be zero-length) to signal end-of-stream. After `last = true` has been passed,
/// subsequent calls are silently ignored.
///
/// Returns `true` if at least one non-ASCII byte has been seen so far; `false` if only ASCII
/// has been observed.
///
/// # Safety
/// - `opaque` must be a valid pointer returned by `rust_encoding_detector_new` that has not
///   yet been freed.
/// - `buffer` must point to a valid byte slice of `buffer_len` bytes, or be null if
///   `buffer_len` is 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_encoding_detector_feed(
    opaque: *mut OpaqueEncodingDetector,
    buffer: *const u8,
    buffer_len: usize,
    last: bool,
) -> bool {
    unsafe {
        crate::abort_on_panic(|| {
            let Some(o) = opaque.as_mut() else {
                return false;
            };
            if o.finished {
                return false;
            }
            let slice = crate::bytes_from_raw(buffer, buffer_len).unwrap_or(&[]);
            let has_non_ascii = o.detector.feed(slice, last);
            if last {
                o.finished = true;
            }
            has_non_ascii
        })
    }
}

/// Query the current encoding guess from the streaming detector.
///
/// May be called at any time after one or more `rust_encoding_detector_feed` calls, including
/// before end-of-stream. Returns the best guess based on the bytes seen so far.
///
/// `tld` must follow the same constraints as in `rust_detect_encoding`: rightmost DNS label,
/// lowercase ASCII only, no dots. Pass null / 0 for a generic (`.com`-equivalent) guess.
///
/// On success writes the encoding name pointer and length to `out_encoding_name` /
/// `out_encoding_name_len` and returns `true`. Returns `false` only if `opaque` is null.
///
/// # Safety
/// - `opaque` must be valid and not yet freed.
/// - `tld` constraints same as `rust_detect_encoding`.
/// - `out_encoding_name` and `out_encoding_name_len` must be non-null writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_encoding_detector_guess(
    opaque: *const OpaqueEncodingDetector,
    tld: *const u8,
    tld_len: usize,
    out_encoding_name: *mut *const u8,
    out_encoding_name_len: *mut usize,
) -> bool {
    unsafe {
        crate::abort_on_panic(|| {
            let Some(o) = opaque.as_ref() else {
                return false;
            };
            let tld_slice = if tld.is_null() || tld_len == 0 {
                None
            } else {
                Some(std::slice::from_raw_parts(tld, tld_len))
            };
            let encoding = o.detector.guess(tld_slice, Utf8Detection::Deny);
            let name = encoding.name().as_bytes();
            *out_encoding_name = name.as_ptr();
            *out_encoding_name_len = name.len();
            true
        })
    }
}

/// Destroy a streaming detector created by `rust_encoding_detector_new`.
///
/// Passing null is a no-op. The pointer must not be used after this call.
///
/// # Safety
/// `opaque` must be either null or a valid pointer returned by `rust_encoding_detector_new`
/// that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_encoding_detector_free(opaque: *mut OpaqueEncodingDetector) {
    if !opaque.is_null() {
        unsafe {
            drop(Box::from_raw(opaque));
        }
    }
}
