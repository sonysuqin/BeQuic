#include "net/tools/quic/be_quic_client_message_loop_network_helper.h"

namespace net {

BeQuicClientMessageLooplNetworkHelper::BeQuicClientMessageLooplNetworkHelper(
    quic::QuicChromiumClock* clock,
    quic::QuicClientBase* client)
    : QuicClientMessageLooplNetworkHelper(clock, client) {}

BeQuicClientMessageLooplNetworkHelper::~BeQuicClientMessageLooplNetworkHelper() = default;

bool BeQuicClientMessageLooplNetworkHelper::CreateUDPSocketAndBind(
    quic::QuicSocketAddress server_address,
    quic::QuicIpAddress bind_to_address,
    int bind_to_port) {
    if (!socket_created_) {
        socket_created_ =
            QuicClientMessageLooplNetworkHelper::CreateUDPSocketAndBind(server_address, bind_to_address, bind_to_port);
    }
    return socket_created_;
}

}  // namespace net
