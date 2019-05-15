#ifndef __BE_QUIC_SPDY_CLIENT_STREAM_H__
#define __BE_QUIC_SPDY_CLIENT_STREAM_H__

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_client_stream.h"
#include "net/tools/quic/be_quic_spdy_data_delegate.h"
#include "net/tools/quic/streambuf.hpp"
#include "base/synchronization/lock.h"

namespace quic {

class BeQuicSpdyClientStream : public QuicSpdyClientStream {
public:
    BeQuicSpdyClientStream(QuicStreamId id, QuicSpdyClientSession* session, StreamType type);

    BeQuicSpdyClientStream(PendingStream pending, QuicSpdyClientSession* spdy_session, StreamType type);

    BeQuicSpdyClientStream(const BeQuicSpdyClientStream&) = delete;

    BeQuicSpdyClientStream& operator=(const BeQuicSpdyClientStream&) = delete;

    ~BeQuicSpdyClientStream() override;

public:
    //Rewrite OnInitialHeadersComplete for saving "content-length".
    //Since parent's content_length_ is private, no way to get it without modify source code, 
    //so re-parse once again.
    void OnInitialHeadersComplete(
        bool fin,
        size_t frame_len,
        const QuicHeaderList& header_list) override;

    //Rewrite OnBodyAvailable for reporting data to up lever in real-time, for stream live time is short.
    void OnBodyAvailable() override;

    //Rewrite OnClose.
    void OnClose() override;

    //Delegate to receive content data.
    void set_delegate(std::weak_ptr<net::BeQuicSpdyDataDelegate> data_delegate) { data_delegate_ = data_delegate; }

    //Return re-parsed content-length, now it's public.    
    int64_t content_length() { return content_length_; }

    //Check if content length available, or will parse from header.
    int64_t check_content_length();

private:
    int64_t content_length_ = -1;
    uint64_t accumulated_length_ = 0;
    std::weak_ptr<net::BeQuicSpdyDataDelegate> data_delegate_;
};

}  // namespace quic

#endif  // __BE_QUIC_SPDY_CLIENT_STREAM_H__
