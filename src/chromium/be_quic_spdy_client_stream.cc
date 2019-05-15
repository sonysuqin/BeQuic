#include "net/tools/quic/be_quic_spdy_client_stream.h"
#include "net/third_party/quiche/src/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_map_util.h"

namespace quic {

BeQuicSpdyClientStream::BeQuicSpdyClientStream(QuicStreamId id, QuicSpdyClientSession* session, StreamType type)
    : QuicSpdyClientStream(id, session, type) {

}

BeQuicSpdyClientStream::BeQuicSpdyClientStream(PendingStream pending, QuicSpdyClientSession* spdy_session, StreamType type)
    : QuicSpdyClientStream(std::move(pending), spdy_session, type) {

}

BeQuicSpdyClientStream::~BeQuicSpdyClientStream() {

}

void BeQuicSpdyClientStream::OnInitialHeadersComplete(
      bool fin,
      size_t frame_len,
      const QuicHeaderList& header_list) {
    QuicSpdyClientStream::OnInitialHeadersComplete(fin, frame_len, header_list);
    check_content_length();

#ifdef _DEBUG
    const spdy::SpdyHeaderBlock& headers = QuicSpdyClientStream::response_headers();
    LOG(INFO) << "Headers: " << std::endl;
    auto iter = headers.begin();
    for (;iter != headers.end();++iter) {
        LOG(INFO) << iter->first << ": " << iter->second << std::endl;
    }
#endif
}

void BeQuicSpdyClientStream::OnBodyAvailable() {
    if (visitor() == nullptr) {
        return;
    }

    while (HasBytesToRead()) {
        struct iovec iov;
        if (GetReadableRegions(&iov, 1) == 0) {
            // No more data to read.
            break;
        }

        QUIC_DVLOG(1) << "Client processed " << iov.iov_len << " bytes for stream " << id();
        std::shared_ptr<net::BeQuicSpdyDataDelegate> data_delegate = data_delegate_.lock();
        if (data_delegate) {
            data_delegate->on_data(this, static_cast<char*>(iov.iov_base), iov.iov_len);
        }

        accumulated_length_ += iov.iov_len;

        if (content_length_ >= 0 &&
            accumulated_length_ > static_cast<uint64_t>(content_length_)) {
            QUIC_DLOG(ERROR)
                << "Invalid content length ("
                << content_length_ << ") with data of size "
                << accumulated_length_;
            Reset(QUIC_BAD_APPLICATION_PAYLOAD);
            return;
        }
        MarkConsumed(iov.iov_len);
    }

    if (sequencer()->IsClosed()) {
        OnFinRead();
    } else {
        sequencer()->SetUnblocked();
    }
}

void BeQuicSpdyClientStream::OnClose() {
    LOG(INFO) << "Stream " << id() << " closed."<< std::endl;
    quic::QuicSpdyStream::OnClose();
}

int64_t BeQuicSpdyClientStream::check_content_length() {
    if (content_length_ > 0) {
        return content_length_;
    }

    const spdy::SpdyHeaderBlock& headers = QuicSpdyClientStream::response_headers();
    if (QuicContainsKey(headers, "content-length")) {
        SpdyUtils::ExtractContentLengthFromHeaders(&content_length_, (spdy::SpdyHeaderBlock*)&headers);
    }

    return content_length_;
}

}  // namespace quic
