#include "net/tools/quic/be_quic_spdy_client.h"
#include "net/tools/quic/be_quic_spdy_client_session.h"
#include "net/tools/quic/be_quic_define.h"

namespace net {

BeQuicSpdyClient::BeQuicSpdyClient(
        quic::QuicSocketAddress server_address,
        const quic::QuicServerId& server_id,
        const quic::ParsedQuicVersionVector& supported_versions,
        std::unique_ptr<quic::ProofVerifier> proof_verifier)
    : QuicSimpleClient(
        server_address,
        server_id,
        supported_versions,
        std::move(proof_verifier)),
      istream_(&response_buff_),
      ostream_(&response_buff_) {

}

BeQuicSpdyClient::~BeQuicSpdyClient() {

}

std::unique_ptr<quic::QuicSession> BeQuicSpdyClient::CreateQuicClientSession(
        const quic::ParsedQuicVersionVector& supported_versions,
        quic::QuicConnection* connection) {
    std::unique_ptr<quic::BeQuicSpdyClientSession> session = quic::QuicMakeUnique<quic::BeQuicSpdyClientSession>(
        *config(),
        supported_versions,
        connection,
        server_id(),
        crypto_config(),
        push_promise_index());
    session.get()->set_delegate(shared_from_this());
    return session;
}

int BeQuicSpdyClient::read_body(unsigned char *buf, int size) {
    int ret = 0;
    do {
        if (buf == NULL || size == 0) {
            ret = kBeQuicErrorCode_Invalid_Param;
            break;
        }

        //TBD:Trunk?
        if (content_length_ > 0 && read_offset_ >= content_length_) {
            ret = kBeQuicErrorCode_Eof;
            break;
        }

        base::AutoLock lock(mutex_);
        size_t read_len = std::min<size_t>((size_t)size, response_buff_.size());
        if (read_len == 0) {
            break;
        }

        istream_.read((char*)buf, read_len);
        read_offset_ += read_len;
        ret = (int)read_len;
    } while (0);
    return ret;
}

void BeQuicSpdyClient::on_data(quic::QuicSpdyClientStream *stream, char *buf, int size) {
    if (stream == NULL) {
        return;
    }
    
    if (content_length_ == -1) {
        quic::BeQuicSpdyClientStream* bequic_stream = static_cast<quic::BeQuicSpdyClientStream*>(stream);
        content_length_ = bequic_stream->content_length();
    }

    if (buf != NULL && size > 0) {
        base::AutoLock lock(mutex_);
        ostream_.write(buf ,size);
    }
}

}  // namespace net
