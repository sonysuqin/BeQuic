#ifndef __BE_QUIC_CLIENT_H__
#define __BE_QUIC_CLIENT_H__

#include "net/tools/quic/be_quic_define.h"
#include "net/tools/quic/be_quic_spdy_client.h"
#include "base/threading/simple_thread.h"

#include <memory>
#include <vector>
#include <future>
#include <atomic>

namespace net {

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
class BeQuicClient : public base::SimpleThread {
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
        int timeout);

    void close();

    int read_body(unsigned char *buf, int size, int timeout);

    int64_t seek(int64_t off, int whence);

    int64_t seek_from_net(int64_t off);

    bool check_seeking();

    int get_handle() { return handle_; }
    
    void Run() override;

private:
    void run_event_loop();

    void run_idle_loop();    

    int internal_request(
        const std::string& url,
        const std::string& mapped_ip,
        unsigned short mapped_port,
        const std::string& method,
        std::vector<InternalQuicHeader> headers,
        const std::string& body,
        bool verify_certificate);

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
    bool verify_certificate_ = true;
    std::shared_ptr<std::promise<int> > open_promise_;
    std::shared_ptr<std::promise<int64_t> > seek_promise_;
    std::atomic_bool busy_;
    std::atomic_bool running_;
    std::atomic_bool seeking_;
    std::mutex mutex_;
    std::condition_variable cond_; //Closing and seeking condition.
    int64_t seek_offset_ = -1;
};

}  // namespace net

#endif  // __BE_QUIC_CLIENT_H__
