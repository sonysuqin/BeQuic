#ifndef __BE_QUIC_SPDY_CLIENT_H__
#define __BE_QUIC_SPDY_CLIENT_H__

#include "net/tools/quic/quic_simple_client.h"
#include "net/tools/quic/be_quic_spdy_client_stream.h"
#include "net/tools/quic/be_quic_spdy_data_delegate.h"
#include "base/synchronization/condition_variable.h"

#include <mutex>
#include <condition_variable>

namespace net {

class BeQuicSpdyClient
    : public QuicSimpleClient, 
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

    bool close_current_stream();

    void on_data(quic::QuicSpdyClientStream *stream, char *buf, int size) override;

private:
    bool is_buffer_sufficient();

private:
    std::mutex mutex_;
    std::condition_variable cond_;
    //Parent class save body content in std::string, causing increasing memory
    //when downloaing big file, so repace it with streambuf from boost::asio.
    boost::asio::streambuf response_buff_;
    std::istream istream_;
    std::ostream ostream_;
    bool got_first_data_ = false;
    int64_t content_length_ = -1;
    int64_t read_offset_ = 0;
    quic::QuicStreamId current_stream_id_ = 0;
};

}  // namespace net

#endif  // __BE_QUIC_SPDY_CLIENT_H__
