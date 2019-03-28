#include "net/tools/quic/be_quic_client_manager.h"

namespace net {

BeQuicClientManager::Ptr BeQuicClientManager::instance_(new BeQuicClientManager());

BeQuicClientManager::BeQuicClientManager() {

}

BeQuicClientManager::~BeQuicClientManager() {

}

BeQuicClientManager::Ptr BeQuicClientManager::instance() {
    return instance_;
}

BeQuicClient::Ptr BeQuicClientManager::create_client() {
    base::AutoLock lock(mutex_);
    int handle = index_++;
    BeQuicClient::Ptr client(new BeQuicClient(handle));
    client_table_[handle] = client;
    return client;
}

void BeQuicClientManager::release_client(int handle) {
    base::AutoLock lock(mutex_);
    auto iter = client_table_.find(handle);
    if (iter != client_table_.end()) {
        client_table_.erase(iter);
    }
}

void BeQuicClientManager::close_and_release_client(int handle) {
    base::AutoLock lock(mutex_);
    auto iter = client_table_.find(handle);
    if (iter != client_table_.end()) {
        BeQuicClient::Ptr client = iter->second;
        client->close();
        client_table_.erase(iter);
    }
}

BeQuicClient::Ptr BeQuicClientManager::get_client(int handle) {
    base::AutoLock lock(mutex_);
    auto iter = client_table_.find(handle);
    if (iter != client_table_.end()) {
        return iter->second;
    } else {
        return BeQuicClient::Ptr();
    }
}

}  // namespace net
