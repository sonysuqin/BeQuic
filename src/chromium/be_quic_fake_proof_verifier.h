#ifndef __BE_QUIC_FAKE_PROOF_VERIFIER__
#define __BE_QUIC_FAKE_PROOF_VERIFIER__

#include "net/third_party/quiche/src/quic/core/crypto/proof_verifier.h"

namespace quic {

class BeQuicFakeProofVerifier : public quic::ProofVerifier {
public:
    quic::QuicAsyncStatus VerifyProof(
        const std::string& hostname,
        const uint16_t port,
        const std::string& server_config,
        quic::QuicTransportVersion quic_version,
        quic::QuicStringPiece chlo_hash,
        const std::vector<std::string>& certs,
        const std::string& cert_sct,
        const std::string& signature,
        const quic::ProofVerifyContext* context,
        std::string* error_details,
        std::unique_ptr<quic::ProofVerifyDetails>* details,
        std::unique_ptr<quic::ProofVerifierCallback> callback) override;

    quic::QuicAsyncStatus VerifyCertChain(
        const std::string& hostname,
        const std::vector<std::string>& certs,
        const quic::ProofVerifyContext* verify_context,
        std::string* error_details,
        std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
        std::unique_ptr<quic::ProofVerifierCallback> callback) override;

    std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override;
};

} // namespace quic

#endif // #ifndef __BE_QUIC_FAKE_PROOF_VERIFIER__
