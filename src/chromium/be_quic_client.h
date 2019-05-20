#ifndef __BE_QUIC_CLIENT_H__
#define __BE_QUIC_CLIENT_H__

#include "net/tools/quic/be_quic_define.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/simple_thread.h"
#include "net/tools/quic/be_quic_spdy_client.h"
#include "net/tools/quic/be_quic_spdy_data_delegate.h"
#include "net/tools/quic/streambuf.hpp"

#include <memory>
#include <vector>
#include <future>
#include <atomic>
#include <mutex>
#include <condition_variable>

namespace net {

////////////////////////////////////Promise//////////////////////////////////////
typedef std::promise<int> IntPromise;
typedef std::shared_ptr<IntPromise> IntPromisePtr;
typedef std::shared_future<int> IntFuture;

////////////////////////////////////InternalQuicHeader//////////////////////////////////////
typedef struct InternalQuicHeader {
    std::string key;
    std::string value;

    InternalQuicHeader(const std::string &k, const std::string &v) {
        key     = k;
        value   = v;
    }
} InternalQuicHeader;

////////////////////////////////////BeQuicClient//////////////////////////////////////
class BeQuicClient : 
    public base::SimpleThread, 
    public BeQuicSpdyDataDelegate,
    public std::enable_shared_from_this<BeQuicClient> {
public:
    typedef std::shared_ptr<BeQuicClient> Ptr;

    BeQuicClient(int handle);

    ~BeQuicClient() override;

public:
    int open(
        const std::string& url,
        const char *ip,
        unsigned short port,
        const std::string& method,
        std::vector<InternalQuicHeader> headers,
        const std::string& body,
        bool verify_certificate,
        int ietf_draft_version,
        int handshake_version,
        int transport_version,
        int block_size,
        int block_consume,
        int timeout);

    void close();

    int read_buffer(unsigned char *buf, int size, int timeout);

    int64_t seek(int64_t off, int whence);

    int get_stats(BeQuicStats *stats);

    int get_handle() { return handle_; }

    void on_data(quic::QuicSpdyClientStream *stream, char *buf, int size) override;
    
    void Run() override;

private:
    void run_event_loop();

    int internal_request(
        const std::string& url,
        const std::string& mapped_ip,
        unsigned short mapped_port,
        const std::string& method,
        std::vector<InternalQuicHeader> headers,
        const std::string& body,
        bool verify_certificate,
        int ietf_draft_version,
        int handshake_version,
        int transport_version,
        int block_size,
        int block_consume);

    void seek_internal(int64_t off, int whence, IntPromisePtr promise);

    int64_t seek_in_buffer(int64_t off, int whence, int64_t *target_off);

    int64_t seek_from_net(int64_t off);

    void get_stats_internal(BeQuicStats *stats, IntPromisePtr promise);

    bool close_current_stream();

    bool is_buffer_sufficient();

private:
    int handle_ = -1;
    std::shared_ptr<BeQuicSpdyClient> spdy_quic_client_;
    spdy::SpdyHeaderBlock header_block_;
    std::string url_;
    std::string mapped_ip_;
    unsigned short mapped_port_ = 0;
    std::string method_;
    std::vector<InternalQuicHeader> headers_;
    std::string body_;
    bool verify_certificate_    = true;
    int ietf_draft_version_     = -1;
    int handshake_version_      = -1;
    int transport_version_      = -1;
    int block_size_             = -1;
    int block_consume_          = -1;
    IntPromisePtr open_promise_;
    std::atomic_bool busy_;     //Flag indicate if invoke thread called open/close.
    std::atomic_bool running_;  //Flag indicate if worker thread running.
    base::MessageLoopForIO *message_loop_ = NULL;
    base::RunLoop *run_loop_    = NULL;
    base::Time start_time_;
    int64_t resolve_time_       = 0;
    int64_t connect_time_       = 0;

    //Buffer relate.
    std::mutex data_mutex_;
    std::condition_variable data_cond_;
    boost::asio::streambuf response_buff_;
    std::istream istream_;
    std::ostream ostream_;
    bool got_first_data_    = false;
    int64_t content_length_ = -1;
    int64_t read_offset_    = 0;
    quic::QuicStreamId current_stream_id_ = 0;
    base::Time first_data_time_;
};

}  // namespace net

#endif  // __BE_QUIC_CLIENT_H__
