#ifndef __BE_QUIC_CLIENT_H__
#define __BE_QUIC_CLIENT_H__

#include "net/tools/quic/quic_simple_client.h"
#include "base/synchronization/lock.h"

#include <memory>

namespace net {

class BeQuicClient : public QuicSimpleClient {
public:
    typedef std::shared_ptr<BeQuicClient> Ptr;

    BeQuicClient(
        quic::QuicSocketAddress server_address,
        const quic::QuicServerId& server_id,
        const quic::ParsedQuicVersionVector& supported_versions,
        std::unique_ptr<quic::ProofVerifier> proof_verifier,
        int handle);

    ~BeQuicClient() override;
    
public:
    int get_handle() { return handle_; }

private:
    int handle_ = -1;
};

}  // namespace net

#endif  // __BE_QUIC_CLIENT_H__
