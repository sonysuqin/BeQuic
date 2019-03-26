#include "net/tools/quic/be_quic_client.h"

namespace net {

BeQuicClient::BeQuicClient(
    quic::QuicSocketAddress server_address,
    const quic::QuicServerId& server_id,
    const quic::ParsedQuicVersionVector& supported_versions,
    std::unique_ptr<quic::ProofVerifier> proof_verifier,
    int handle)
    : QuicSimpleClient(
          server_address,
          server_id,
          supported_versions,
          std::move(proof_verifier)),
      handle_(handle) {
    LOG(INFO) << "BeQuicClient created " << handle_ << std::endl; 
}

BeQuicClient::~BeQuicClient() {
    LOG(INFO) << "BeQuicClient deleted " << handle_ << std::endl;
}

}  // namespace net
