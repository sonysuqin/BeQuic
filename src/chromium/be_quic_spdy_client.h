#ifndef __BE_QUIC_SPDY_CLIENT_H__
#define __BE_QUIC_SPDY_CLIENT_H__

#include "base/command_line.h"
#include "base/macros.h"
#include "base/synchronization/condition_variable.h"
#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/http/http_response_headers.h"
#include "net/log/net_log.h"
#include "net/quic/platform/impl/quic_chromium_clock.h"
#include "net/quic/quic_chromium_packet_reader.h"
#include "net/third_party/quiche/src/quic/core/http/quic_spdy_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/tools/quic_spdy_client_base.h"
#include "net/tools/quic/quic_client_message_loop_network_helper.h"
#include "net/tools/quic/be_quic_spdy_client_stream.h"
#include "net/tools/quic/be_quic_spdy_data_delegate.h"

#include <stddef.h>
#include <memory>
#include <string>
#include <mutex>
#include <condition_variable>

namespace net {
class QuicChromiumAlarmFactory;
class QuicChromiumConnectionHelper;

class BeQuicSpdyClient
    : public quic::QuicSpdyClientBase, 
      public BeQuicSpdyDataDelegate,
      public std::enable_shared_from_this<BeQuicSpdyClient> {
public:
    BeQuicSpdyClient(
        quic::QuicSocketAddress server_address,
        const quic::QuicServerId& server_id,
        const quic::ParsedQuicVersionVector& supported_versions,
        std::unique_ptr<quic::ProofVerifier> proof_verifier);

  ~BeQuicSpdyClient() override;

public:
    std::unique_ptr<quic::QuicSession> CreateQuicClientSession(
        const quic::ParsedQuicVersionVector& supported_versions,
        quic::QuicConnection* connection) override;

    int read_body(unsigned char *buf, int size, int timeout);

    int64_t seek_in_buffer(int64_t off, int whence, int64_t *target_off);

    void set_read_offset(int64_t off) { read_offset_ = off; }

    bool close_current_stream();

    void on_data(quic::QuicSpdyClientStream *stream, char *buf, int size) override;

    const base::Time& get_first_data_time() { return first_data_time_; }

private:
    bool is_buffer_sufficient();

    QuicChromiumAlarmFactory* CreateQuicAlarmFactory();

    QuicChromiumConnectionHelper* CreateQuicConnectionHelper();

private:
    //For block reading.
    std::mutex mutex_;
    std::condition_variable cond_;

    //Parent class save body content in std::string, causing increasing memory
    //when downloaing big file, so replace it with streambuf from boost::asio.
    boost::asio::streambuf response_buff_;
    std::istream istream_;
    std::ostream ostream_;

    //Data flags.
    bool got_first_data_    = false;
    int64_t content_length_ = -1;
    int64_t read_offset_    = 0;

    //Valid after stream created.
    quic::QuicStreamId current_stream_id_ = 0;

    //Timing.
    base::Time first_data_time_;

    //From QuicSimpleClient.
    quic::QuicChromiumClock clock_;
    base::WeakPtrFactory<BeQuicSpdyClient> weak_factory_;
    DISALLOW_COPY_AND_ASSIGN(BeQuicSpdyClient);
};

}  // namespace net

#endif  // __BE_QUIC_SPDY_CLIENT_H__
