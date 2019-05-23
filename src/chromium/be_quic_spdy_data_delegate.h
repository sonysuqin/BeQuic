#ifndef __BE_QUIC_SPDY_DATA_DELEGATE_H__
#define __BE_QUIC_SPDY_DATA_DELEGATE_H__

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_client_stream.h"

namespace net {

class BeQuicSpdyDataDelegate {
public:
    BeQuicSpdyDataDelegate() = default;
    virtual ~BeQuicSpdyDataDelegate() = default;

public:
    virtual void on_stream_created(quic::QuicSpdyClientStream *stream) = 0;
    virtual void on_stream_closed(quic::QuicSpdyClientStream *stream) = 0;
    virtual void on_data(quic::QuicSpdyClientStream *stream, char *buf, int size) = 0;
};

}  // namespace net

#endif  // __BE_QUIC_SPDY_BODY_DELEGATE_H__
