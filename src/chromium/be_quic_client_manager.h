#ifndef __BE_QUIC_CLIENT_MANAGER_H__
#define __BE_QUIC_CLIENT_MANAGER_H__

#include "net/tools/quic/be_quic_client.h"

#include <unordered_map>

namespace net {

class BeQuicClientManager {
public:
    typedef std::shared_ptr<BeQuicClientManager> Ptr;
    static Ptr instance();
    ~BeQuicClientManager();

public:
    BeQuicClient::Ptr create_client();

    void release_client(int handle);
    
    void close_and_release_client(int handle);

    BeQuicClient::Ptr get_client(int handle);

private:
    BeQuicClientManager();
    BeQuicClientManager(const BeQuicClientManager&) = delete;
    BeQuicClientManager& operator=(const BeQuicClientManager&) = delete;

private:
    static Ptr instance_;
    int index_ = 618; // Start from fake "Golden Ratio".
    std::unordered_map<int, BeQuicClient::Ptr> client_table_;
    base::Lock mutex_;
};

}  // namespace net

#endif  // __BE_QUIC_CLIENT_MANAGER_H__
