#ifndef __BE_QUIC_SPDY_CLIENT_SESSION_H__
#define __BE_QUIC_SPDY_CLIENT_SESSION_H__

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_client_session.h"
#include "net/tools/quic/be_quic_spdy_data_delegate.h"

namespace quic {

class BeQuicSpdyClientSession : public QuicSpdyClientSession {
public:
    BeQuicSpdyClientSession(
        const QuicConfig& config,
        const ParsedQuicVersionVector& supported_versions,
        QuicConnection* connection,
        const QuicServerId& server_id,
        QuicCryptoClientConfig* crypto_config,
        QuicClientPushPromiseIndex* push_promise_index);

    BeQuicSpdyClientSession(const QuicSpdyClientSession&) = delete;

    BeQuicSpdyClientSession& operator=(const QuicSpdyClientSession&) = delete;

    ~BeQuicSpdyClientSession() override;

public:
    //Rewrite CreateClientStream to create BeQuicSpdyClientStream.
    std::unique_ptr<QuicSpdyClientStream> CreateClientStream() override;

    //Temp store it here.
    void set_delegate(std::weak_ptr<net::BeQuicSpdyDataDelegate> delegate) { delegate_ = delegate; }

    //Rewrite OnConnectionClosed.
    void OnConnectionClosed(QuicErrorCode error, const std::string& error_details, ConnectionCloseSource source) override;

    //Control ping request.
    bool ShouldKeepConnectionAlive() const override;

private:
    std::weak_ptr<net::BeQuicSpdyDataDelegate> delegate_;
};

}  // namespace quic

#endif  // __BE_QUIC_SPDY_CLIENT_SESSION_H__
