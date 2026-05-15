/*
 * Copyright (c) 2026, Ladybird contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <AK/Debug.h>
#include <LibGC/Function.h>
#include <LibJS/Runtime/Value.h>
#include <LibTextCodec/Decoder.h>
#include <LibWeb/DOM/Document.h>
#include <LibWeb/Fetch/Infrastructure/HTTP/Bodies.h>
#include <LibWeb/HTML/Parser/HTMLEncodingDetection.h>
#include <LibWeb/HTML/Parser/HTMLParser.h>
#include <LibWeb/HTML/Parser/IncrementalDocumentParser.h>
#include <LibWeb/HTML/Parser/RustFFI.h>

namespace Web::HTML {

GC_DEFINE_ALLOCATOR(IncrementalDocumentParser);

GC::Ref<IncrementalDocumentParser> IncrementalDocumentParser::create(GC::Ref<DOM::Document> document, GC::Ref<Fetch::Infrastructure::Body> body, URL::URL url, Optional<MimeSniff::MimeType> mime_type)
{
    return document->realm().create<IncrementalDocumentParser>(document, body, move(url), move(mime_type));
}

IncrementalDocumentParser::IncrementalDocumentParser(GC::Ref<DOM::Document> document, GC::Ref<Fetch::Infrastructure::Body> body, URL::URL url, Optional<MimeSniff::MimeType> mime_type)
    : m_document(document)
    , m_body(body)
    , m_url(move(url))
    , m_mime_type(move(mime_type))
{
}

IncrementalDocumentParser::~IncrementalDocumentParser() = default;

void IncrementalDocumentParser::finalize()
{
    Base::finalize();
    // The streaming detector is normally freed in process_end_of_body (either after confirming
    // the initial encoding or in re_parse_with_encoding). This handles the GC collection path
    // where neither of those ran (e.g. navigation away mid-load).
    if (m_streaming_detector) {
        Parser::rust_encoding_detector_free(m_streaming_detector);
        m_streaming_detector = nullptr;
    }
}

void IncrementalDocumentParser::visit_edges(Cell::Visitor& visitor)
{
    Base::visit_edges(visitor);
    visitor.visit(m_document);
    visitor.visit(m_body);
    visitor.visit(m_parser);
}

void IncrementalDocumentParser::start()
{
    // https://html.spec.whatwg.org/multipage/document-lifecycle.html#read-html
    // The user agent may wait for more bytes of the resource to be available while determining the
    // encoding. Body::wait_for_sniff_bytes waits until its sniff-byte threshold is available, or
    // until the stream closes.
    //
    // FIXME: The spec allows starting the parse after 500 ms or 1024 bytes, whichever comes first.
    // We only honor the byte threshold.
    auto parser = GC::Ref { *this };
    m_body->wait_for_sniff_bytes(GC::create_function(heap(), [parser](ReadonlyBytes sniff_bytes) {
        parser->initialize_parser(sniff_bytes);
    }));
}

void IncrementalDocumentParser::initialize_parser(ReadonlyBytes sniff_bytes)
{
    if (m_parser)
        return;

    // https://html.spec.whatwg.org/multipage/parsing.html#parsing-with-a-known-character-encoding
    // https://html.spec.whatwg.org/multipage/parsing.html#determining-the-character-encoding
    auto sniff_result = m_document->has_encoding()
        ? EncodingSniffResult { m_document->encoding().value().to_byte_string(), false }
        : run_encoding_sniffing_algorithm(m_document, sniff_bytes, m_mime_type);
    auto encoding = sniff_result.encoding;
    auto used_frequency_analysis = sniff_result.used_frequency_analysis;
    dbgln_if(HTML_PARSER_DEBUG, "The incremental HTML parser selected encoding '{}'", encoding);

    auto decoder = TextCodec::decoder_for(encoding);
    VERIFY(decoder.has_value());

    auto standardized_encoding = TextCodec::get_standardized_encoding(encoding);
    VERIFY(standardized_encoding.has_value());
    m_decoder = make<TextCodec::StreamingDecoder>(decoder.value());

    // https://html.spec.whatwg.org/multipage/parsing.html#determining-the-character-encoding
    // The document's character encoding must immediately be set to the value returned from this
    // algorithm, at the same time as the user agent uses the returned value to select the decoder
    // to use for the input byte stream.
    m_document->set_encoding(MUST(String::from_utf8(standardized_encoding.value())));
    m_initial_encoding = ByteString { standardized_encoding.value() };

    // FIXME: Implement the spec's "change the encoding while parsing" algorithm.
    m_document->set_url(m_url);
    m_parser = HTMLParser::create_with_open_input_stream(m_document);

    // If step 8 (chardetng frequency analysis) determined the initial encoding, start a streaming
    // detector so we can re-examine the full document byte stream and potentially re-parse with the
    // correct encoding once all bytes have been seen. BOM, transport-encoding, and prescan results
    // are authoritative and do not need re-examination.
    if (used_frequency_analysis)
        m_streaming_detector = Parser::rust_encoding_detector_new();

    start_incremental_read();
}

void IncrementalDocumentParser::start_incremental_read()
{
    auto parser = GC::Ref { *this };
    m_body->incrementally_read(
        GC::create_function(heap(), [parser](ByteBuffer bytes) mutable {
            parser->process_body_chunk(move(bytes));
        }),
        GC::create_function(heap(), [parser] {
            parser->process_end_of_body();
        }),
        GC::create_function(heap(), [parser](JS::Value error) {
            parser->process_body_error(error);
        }),
        GC::Ref { m_document->realm().global_object() });
}

bool IncrementalDocumentParser::should_continue() const
{
    // NOTE: document.open() replaces m_document->parser() without aborting the old parser, so we have to stop feeding
    //       bytes once we're no longer the document's active parser.
    return m_parser && !m_parser->aborted() && m_document->parser() == m_parser;
}

void IncrementalDocumentParser::append_decoded(StringView decoded)
{
    m_source.append(decoded);
    m_parser->tokenizer().append_to_input_stream(decoded);
}

void IncrementalDocumentParser::process_body_chunk(ByteBuffer bytes)
{
    if (!should_continue())
        return;

    // Accumulate raw bytes and feed the streaming detector so it can see the full stream,
    // not just the sniff-bytes prefix. The ReadableStream replays all bytes from byte 0,
    // so the sniff bytes are included here again — no double-counting with initialize_parser.
    if (m_streaming_detector) {
        MUST(m_raw_bytes.try_append(bytes.bytes()));
        Parser::rust_encoding_detector_feed(m_streaming_detector, bytes.data(), bytes.size(), false);
    }

    // https://html.spec.whatwg.org/multipage/document-lifecycle.html#read-html
    // Each task that the networking task source places on the task queue while fetching runs must
    // fill the parser's input byte stream with the fetched bytes and cause the HTML parser to
    // perform the appropriate processing of the input stream.
    auto decoded = m_decoder->to_utf8(bytes.bytes()).release_value_but_fixme_should_propagate_errors();
    append_decoded(decoded.bytes_as_string_view());
    pump();
}

void IncrementalDocumentParser::process_end_of_body()
{
    if (!should_continue())
        return;

    // If we have a streaming detector, finalize it and check whether the encoding we chose
    // from sniff bytes alone is still the best guess now that we've seen the full stream.
    if (m_streaming_detector) {
        // Signal end-of-stream to chardetng.
        Parser::rust_encoding_detector_feed(m_streaming_detector, nullptr, 0, true);

        // Get the TLD hint for improved accuracy on country-code domains.
        auto tld = extract_tld_hint(m_url);
        u8 const* tld_data = tld.is_empty() ? nullptr : reinterpret_cast<u8 const*>(tld.characters());
        size_t tld_size = tld.is_empty() ? 0 : tld.length();

        u8 const* encoding_name_ptr = nullptr;
        size_t encoding_name_len = 0;
        if (Parser::rust_encoding_detector_guess(m_streaming_detector, tld_data, tld_size,
                &encoding_name_ptr, &encoding_name_len)) {
            auto detected = StringView { reinterpret_cast<char const*>(encoding_name_ptr), encoding_name_len };
            auto standardized = TextCodec::get_standardized_encoding(detected);
            if (standardized.has_value()) {
                ByteString final_encoding { standardized.value() };
                if (final_encoding != m_initial_encoding) {
                    // The full stream reveals a different encoding than the sniff-bytes guess.
                    // Re-parse the document from scratch with the correct encoding.
                    re_parse_with_encoding(final_encoding);
                    return;
                }
            }
        }

        // Encoding confirmed; free the detector before normal end-of-body processing.
        Parser::rust_encoding_detector_free(m_streaming_detector);
        m_streaming_detector = nullptr;
        m_raw_bytes.clear();
    }

    auto decoded = m_decoder->finish().release_value_but_fixme_should_propagate_errors();
    append_decoded(decoded.bytes_as_string_view());

    // https://html.spec.whatwg.org/multipage/document-lifecycle.html#read-html
    // When no more bytes are available, have the parser process the implied EOF character.
    m_document->set_source(m_source.to_string_without_validation());
    m_parser->tokenizer().close_input_stream();
    pump();
}

void IncrementalDocumentParser::process_body_error(JS::Value)
{
    dbgln("FIXME: Load html page with an error if incremental read of body failed.");
    HTMLParser::the_end(m_document, m_parser);
}

void IncrementalDocumentParser::re_parse_with_encoding(ByteString const& new_encoding)
{
    // FIXME: This is a simplified form of the spec's "change the encoding while parsing"
    // algorithm (https://html.spec.whatwg.org/multipage/parsing.html#change-the-encoding).
    // It tears down the entire first-pass parse tree and re-parses from the raw bytes using
    // the corrected encoding. Script execution side-effects from the first pass are not
    // undone, which is a known limitation.

    // Free the streaming detector — it has served its purpose regardless of outcome.
    VERIFY(m_streaming_detector);
    Parser::rust_encoding_detector_free(m_streaming_detector);
    m_streaming_detector = nullptr;

    // Reset accumulated source (will be rebuilt during the re-parse).
    m_source.clear();

    // Remove all nodes created during the first parse.
    m_document->remove_all_children(true);

    // Install the corrected encoding.
    auto decoder = TextCodec::decoder_for(new_encoding);
    VERIFY(decoder.has_value());
    auto standardized_encoding = TextCodec::get_standardized_encoding(new_encoding);
    VERIFY(standardized_encoding.has_value());
    m_decoder = make<TextCodec::StreamingDecoder>(decoder.value());
    m_document->set_encoding(MUST(String::from_utf8(standardized_encoding.value())));

    // Create a fresh parser. HTMLParser::create_with_open_input_stream installs itself as
    // m_document->parser(), so the old parser is automatically superseded; should_continue()
    // will reflect the new parser from this point on.
    m_parser = HTMLParser::create_with_open_input_stream(m_document);

    // Re-decode all accumulated raw bytes through the new decoder and feed them to the parser.
    auto decoded = m_decoder->to_utf8(m_raw_bytes.bytes()).release_value_but_fixme_should_propagate_errors();
    append_decoded(decoded.bytes_as_string_view());

    // Flush any trailing bytes held by the decoder.
    auto tail = m_decoder->finish().release_value_but_fixme_should_propagate_errors();
    append_decoded(tail.bytes_as_string_view());

    // Release the raw byte buffer — it is no longer needed.
    m_raw_bytes.clear();

    // Close the input stream and run the parser to completion.
    m_document->set_source(m_source.to_string_without_validation());
    m_parser->tokenizer().close_input_stream();
    pump();
}

void IncrementalDocumentParser::register_deferred_start()
{
    if (m_document->has_deferred_parser_start())
        return;

    auto parser = GC::Ref { *this };
    m_document->set_deferred_parser_start(GC::create_function(heap(), [parser] {
        parser->pump();
    }));
}

void IncrementalDocumentParser::pump()
{
    if (!should_continue())
        return;

    if (!m_document->ready_to_run_scripts()) {
        register_deferred_start();
        return;
    }

    if (m_parser->stopped())
        return;

    // FIXME: Process link headers (read-html step 3, third paragraph) after the first parser pass.
    if (m_parser->tokenizer().is_input_stream_closed()) {
        m_parser->run_until_completion();
        return;
    }

    if (m_parser->is_paused())
        return;

    m_parser->run();
}

}
