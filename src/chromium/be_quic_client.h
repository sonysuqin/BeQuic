#ifndef __BE_QUIC_CLIENT_H__
#define __BE_QUIC_CLIENT_H__

#include "net/tools/quic/be_quic_define.h"
#include "net/tools/quic/be_quic_spdy_client.h"
#include "base/threading/simple_thread.h"

#include <memory>
#include <vector>
#include <future>

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
        const std::string& method,
        std::vector<InternalQuicHeader> headers,
        const std::string& body,
        bool verify_certificate,
        int timeout);

    void close();

    int read_body(unsigned char *buf, int size);

    int get_handle() { return handle_; }
    
    void Run() override;

private:
    int internal_request(
        const std::string& url,
        const std::string& method,
        std::vector<InternalQuicHeader> headers,
        const std::string& body,
        bool verify_certificate);

private:
    int handle_ = -1;
    std::shared_ptr<BeQuicSpdyClient> spdy_quic_client_;
    std::string url_;
    std::string method_;
    std::vector<InternalQuicHeader> headers_;
    std::string body_;
    bool verify_certificate_ = true;
    std::shared_ptr<std::promise<int> > promise_;
    bool busy_ = false;
    bool running_ = false;
};

}  // namespace net

#endif  // __BE_QUIC_CLIENT_H__
