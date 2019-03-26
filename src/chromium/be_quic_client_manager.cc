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

BeQuicClient::Ptr BeQuicClientManager::create_client(
        quic::QuicSocketAddress server_address,
        const quic::QuicServerId& server_id,
        const quic::ParsedQuicVersionVector& supported_versions,
        std::unique_ptr<quic::ProofVerifier> proof_verifier) {
    base::AutoLock lock(mutex_);
    int handle = index_++;

    BeQuicClient::Ptr client(new BeQuicClient(server_address, server_id, supported_versions, std::move(proof_verifier), handle));
    client->set_initial_max_packet_length(quic::kDefaultMaxPacketSize);

    if (!client->Initialize()) {
        LOG(ERROR) << "Failed to initialize bequic client." << std::endl;    
        return BeQuicClient::Ptr();
    }

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
