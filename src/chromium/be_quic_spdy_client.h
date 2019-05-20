#ifndef __BE_QUIC_SPDY_CLIENT_H__
#define __BE_QUIC_SPDY_CLIENT_H__

#include "base/command_line.h"
#include "base/macros.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_response_headers.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/tools/quic_spdy_client_base.h"
#include "net/tools/quic/be_quic_spdy_data_delegate.h"

#include <stddef.h>
#include <memory>
#include <string>

namespace net {
class QuicChromiumAlarmFactory;
class QuicChromiumConnectionHelper;

class BeQuicSpdyClient : public quic::QuicSpdyClientBase {
public:
    BeQuicSpdyClient(
        quic::QuicSocketAddress server_address,
        const quic::QuicServerId& server_id,
        const quic::ParsedQuicVersionVector& supported_versions,
        std::unique_ptr<quic::ProofVerifier> proof_verifier,
        std::weak_ptr<net::BeQuicSpdyDataDelegate> data_delegate);

  ~BeQuicSpdyClient() override;

public:
    std::unique_ptr<quic::QuicSession> CreateQuicClientSession(
        const quic::ParsedQuicVersionVector& supported_versions,
        quic::QuicConnection* connection) override;

private:
    QuicChromiumAlarmFactory* CreateQuicAlarmFactory();

    QuicChromiumConnectionHelper* CreateQuicConnectionHelper();

private:
    //Data delegate.
    std::weak_ptr<net::BeQuicSpdyDataDelegate> data_delegate_;

    //From QuicSimpleClient.
    quic::QuicChromiumClock clock_;
    base::WeakPtrFactory<BeQuicSpdyClient> weak_factory_;
    DISALLOW_COPY_AND_ASSIGN(BeQuicSpdyClient);
};

}  // namespace net

#endif  // __BE_QUIC_SPDY_CLIENT_H__
