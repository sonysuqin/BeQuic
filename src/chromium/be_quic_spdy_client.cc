#include "net/tools/quic/be_quic_spdy_client.h"
#include "net/tools/quic/be_quic_spdy_client_session.h"
#include "net/tools/quic/be_quic_define.h"
#include "net/tools/quic/be_quic_client_message_loop_network_helper.h"

#include "base/logging.h"
#include "base/run_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/net_errors.h"
#include "net/http/http_request_info.h"
#include "net/http/http_response_info.h"
#include "net/log/net_log_source.h"
#include "net/log/net_log_with_source.h"
#include "net/quic/quic_chromium_alarm_factory.h"
#include "net/quic/quic_chromium_connection_helper.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/quic/quic_chromium_packet_writer.h"
#include "net/socket/udp_client_socket.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quic/core/http/spdy_utils.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/spdy/core/spdy_header_block.h"

#include <utility>

namespace net {

BeQuicSpdyClient::BeQuicSpdyClient(
    quic::QuicSocketAddress server_address,
    const quic::QuicServerId& server_id,
    const quic::ParsedQuicVersionVector& supported_versions,
    std::unique_ptr<quic::ProofVerifier> proof_verifier,
    std::weak_ptr<net::BeQuicSpdyDataDelegate> data_delegate)
    : quic::QuicSpdyClientBase(
        server_id,
        supported_versions,
        quic::QuicConfig(),
        CreateQuicConnectionHelper(),
        CreateQuicAlarmFactory(),
        quic::QuicWrapUnique(new BeQuicClientMessageLooplNetworkHelper(&clock_, this)),
        std::move(proof_verifier)),
      data_delegate_(data_delegate),
      weak_factory_(this) {
    set_server_address(server_address);
}

BeQuicSpdyClient::~BeQuicSpdyClient() {
    if (connected()) {
        session()->connection()->CloseConnection(
            quic::QUIC_PEER_GOING_AWAY,
            "Shutting down",
            quic::ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    }
}

QuicChromiumConnectionHelper* BeQuicSpdyClient::CreateQuicConnectionHelper() {
    return new QuicChromiumConnectionHelper(&clock_, quic::QuicRandom::GetInstance());
}

QuicChromiumAlarmFactory* BeQuicSpdyClient::CreateQuicAlarmFactory() {
    return new QuicChromiumAlarmFactory(base::ThreadTaskRunnerHandle::Get().get(), &clock_);
}

std::unique_ptr<quic::QuicSession> BeQuicSpdyClient::CreateQuicClientSession(
        const quic::ParsedQuicVersionVector& supported_versions,
        quic::QuicConnection* connection) {
    std::unique_ptr<quic::BeQuicSpdyClientSession> session = quic::QuicMakeUnique<quic::BeQuicSpdyClientSession>(
        *config(),
        supported_versions,
        connection,
        server_id(),
        crypto_config(),
        push_promise_index());
    session.get()->set_delegate(data_delegate_);
    return session;
}

}  // namespace net
