/*
 * Copyright (c) 2026, Ladybird contributors
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <AK/ByteBuffer.h>
#include <AK/ByteString.h>
#include <AK/Optional.h>
#include <AK/OwnPtr.h>
#include <AK/StringBuilder.h>
#include <LibJS/Heap/Cell.h>
#include <LibTextCodec/Decoder.h>
#include <LibURL/URL.h>
#include <LibWeb/Export.h>
#include <LibWeb/Forward.h>
#include <LibWeb/MimeSniff/MimeType.h>

namespace Web::HTML {

class WEB_API IncrementalDocumentParser final : public JS::Cell {
    GC_CELL(IncrementalDocumentParser, JS::Cell);
    GC_DECLARE_ALLOCATOR(IncrementalDocumentParser);

public:
    static constexpr bool OVERRIDES_FINALIZE = true;

    static GC::Ref<IncrementalDocumentParser> create(GC::Ref<DOM::Document>, GC::Ref<Fetch::Infrastructure::Body>, URL::URL, Optional<MimeSniff::MimeType>);

    virtual ~IncrementalDocumentParser() override;

    void start();

private:
    IncrementalDocumentParser(GC::Ref<DOM::Document>, GC::Ref<Fetch::Infrastructure::Body>, URL::URL, Optional<MimeSniff::MimeType>);

    virtual void finalize() override;
    virtual void visit_edges(Cell::Visitor&) override;

    void initialize_parser(ReadonlyBytes sniff_bytes);
    void start_incremental_read();
    void process_body_chunk(ByteBuffer);
    void process_end_of_body();
    void process_body_error(JS::Value);

    void re_parse_with_encoding(ByteString const&);

    void append_decoded(StringView);
    void pump();
    void register_deferred_start();
    bool should_continue() const;

    GC::Ref<DOM::Document> m_document;
    GC::Ref<Fetch::Infrastructure::Body> m_body;
    URL::URL m_url;
    Optional<MimeSniff::MimeType> m_mime_type;

    GC::Ptr<HTMLParser> m_parser;
    OwnPtr<TextCodec::StreamingDecoder> m_decoder;

    StringBuilder m_source;

    // NOTE: Cannot use OwnPtr<OpaqueEncodingDetector, Deleter> because the type is
    // incomplete (defined only in Rust), and AK's OwnPtr instantiates DefaultDelete<T>
    // internally in move-assignment, which requires a complete type.
    Parser::OpaqueEncodingDetector* m_streaming_detector { nullptr };
    // Raw (encoded) bytes accumulated for a potential re-parse.
    ByteBuffer m_raw_bytes;
    // The encoding chosen by run_encoding_sniffing_algorithm; compared against the final
    // streaming-detector guess to decide whether a re-parse is necessary.
    ByteString m_initial_encoding;
};

}
