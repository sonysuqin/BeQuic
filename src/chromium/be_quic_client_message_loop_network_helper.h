#ifndef __BE_QUIC_CLIENT_MESSAGE_LOOP_NETWORK_HELPER_H__
#define __BE_QUIC_CLIENT_MESSAGE_LOOP_NETWORK_HELPER_H__

#include "net/tools/quic/quic_client_message_loop_network_helper.h"

namespace net {

class BeQuicClientMessageLooplNetworkHelper : public QuicClientMessageLooplNetworkHelper {
 public:
    BeQuicClientMessageLooplNetworkHelper(
        quic::QuicChromiumClock* clock, quic::QuicClientBase* client);

    ~BeQuicClientMessageLooplNetworkHelper() override;

public:
    bool CreateUDPSocketAndBind(
        quic::QuicSocketAddress server_address,
        quic::QuicIpAddress bind_to_address,
        int bind_to_port) override;

 private:
    bool socket_created_ = false;
    DISALLOW_COPY_AND_ASSIGN(BeQuicClientMessageLooplNetworkHelper);
};

}  // namespace net

#endif  // __BE_QUIC_CLIENT_MESSAGE_LOOP_NETWORK_HELPER_H__
