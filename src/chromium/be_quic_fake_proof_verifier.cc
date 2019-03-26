#include "net/tools/quic/be_quic_fake_proof_verifier.h"

namespace quic {

quic::QuicAsyncStatus BeQuicFakeProofVerifier::VerifyProof(
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
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
    return quic::QUIC_SUCCESS;
}

quic::QuicAsyncStatus BeQuicFakeProofVerifier::VerifyCertChain(
    const std::string& hostname,
    const std::vector<std::string>& certs,
    const quic::ProofVerifyContext* verify_context,
    std::string* error_details,
    std::unique_ptr<quic::ProofVerifyDetails>* verify_details,
    std::unique_ptr<quic::ProofVerifierCallback> callback) {
    return quic::QUIC_SUCCESS;
}

std::unique_ptr<quic::ProofVerifyContext> BeQuicFakeProofVerifier::CreateDefaultContext() {
    return nullptr;
}

} // namespace quic
