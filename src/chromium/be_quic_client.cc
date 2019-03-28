#include "net/tools/quic/be_quic_client.h"
#include "net/tools/quic/be_quic_fake_proof_verifier.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/base/address_list.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"
#include "net/third_party/quiche/src/quic/tools/quic_client_base.h"
#include "net/third_party/quiche/src/spdy/core/spdy_header_block.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "url/gurl.h"

using net::CertVerifier;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using quic::ProofVerifier;
using net::ProofVerifierChromium;
using quic::QuicStringPiece;
using quic::QuicTextUtils;
using net::TransportSecurityState;
using spdy::SpdyHeaderBlock;

namespace net {

BeQuicClient::BeQuicClient(int handle)
    : base::SimpleThread("BeQuic"),
      handle_(handle) {
    LOG(INFO) << "BeQuicClient created " << handle_ << std::endl;
}

BeQuicClient::~BeQuicClient() {
    LOG(INFO) << "BeQuicClient deleted " << handle_ << std::endl;
}

int BeQuicClient::open(
    const std::string& url,
    const std::string& method,
    std::vector<InternalQuicHeader> headers,
    const std::string& body,
    bool verify_certificate,
    int timeout) {
    int ret = 0;
    do {
        if (url.empty()) {
            ret = kBeQuicErrorCode_Invalid_Param;
            break;
        }

        if (busy_) {
            ret = kBeQuicErrorCode_Invalid_State;
            break;
        }
        
        //Save parameters.
        url_                = url;
        method_             = method;
        headers_            = headers;
        body_               = body;
        verify_certificate_ = verify_certificate;

        //Create promise for blocking wait.
        if (timeout != 0) {
            promise_.reset(new std::promise<int>);
        }

        //Start thread.
        Start();

        //Set busy flag.
        busy_ = true;

        //If won't blocking.
        if (!promise_)  {
            break;
        }

        //Wait forever if timeout set to -1.
        std::shared_future<int> future = promise_->get_future();
        if (timeout < 0) {
            ret = future.get(); //Blocking.
            break;
        }
        
        //Wait for certain time.
        std::future_status status = 
            future.wait_until(std::chrono::system_clock::now() + std::chrono::milliseconds(timeout));
        if (status == std::future_status::ready) {
            ret = future.get();
            break;
        }

        ret = kBeQuicErrorCode_Timeout;
    } while (0);
    return ret;
}

void BeQuicClient::close() {
    if (!busy_) {
        return;
    }

    //Stop thread.
    running_ = false;

    //Wait for thread.
    Join();

    //Reset all members.
    url_                    = "";
    method_                 = "";
    body_                   = "";
    verify_certificate_     = true;
    busy_                   = false;
    headers_.clear();
}

int BeQuicClient::read_body(unsigned char *buf, int size) {
    int ret = 0;
    do {
        if (spdy_quic_client_ == NULL) {
            ret = kBeQuicErrorCode_Invalid_State;
            break;
        }

        ret = spdy_quic_client_->read_body(buf, size);
    } while (0);
    return ret;
}

void BeQuicClient::Run() {
    LOG(INFO) << "Thread handle " << handle_ << " run." << std::endl;

    //Thread is running now.
    running_ = true;

    //Bind message loop.
    base::MessageLoopForIO message_loop;

    do {
        //Internal request.
        int ret = internal_request(
            url_,
            method_,
            headers_,
            body_,
            verify_certificate_);
        if (ret != kBeQuicErrorCode_Success) {
            break;
        }

        //Content message loop.
        while (running_ && spdy_quic_client_ && spdy_quic_client_->WaitForEvents()) {

        }
    } while (0);

    //Disconnect quic client in this thread.
    if (spdy_quic_client_) {
        spdy_quic_client_->Disconnect();
        spdy_quic_client_.reset();
    }

    //Release promise if any.
    if (promise_) {
        promise_->set_value(0);
        promise_.reset();
    }

    LOG(INFO) << "Thread handle " << handle_ << " exit." << std::endl;
}

int BeQuicClient::internal_request(
    const std::string& url,
    const std::string& method,
    std::vector<InternalQuicHeader> headers,
    const std::string& body,
    bool verify_certificate) {
    int ret = kBeQuicErrorCode_Success;
    do {
        //Parse host and port from url.
        GURL gurl(url);
        std::string host    = gurl.host();
        int port            = gurl.EffectiveIntPort();
        
        LOG(INFO) << "BeQuicOpen " << host << ":" << port << " => " << url << "," << method << std::endl;

        //Resolve host to address synchronously.
        net::AddressList addresses;
        if (net::SynchronousHostResolver::Resolve(host, &addresses) != net::OK) {
            ret = kBeQuicErrorCode_Resolve_Fail;
            break;
        }

        //Make up QuicIpAddress.
        quic::QuicIpAddress ip_addr = quic::QuicIpAddress(quic::QuicIpAddressImpl(addresses[0].address()));
        LOG(INFO) << "Resolve to " << ip_addr.ToString() << std::endl;

        //Make up serverid.
        quic::QuicServerId serverId(gurl.host(), gurl.EffectiveIntPort(), net::PRIVACY_MODE_DISABLED);

        //Get Quic version.
        quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();

        //Create certificate verifier.
        std::unique_ptr<CertVerifier>           cert_verifier(CertVerifier::CreateDefault());
        std::unique_ptr<TransportSecurityState> transport_security_state(new TransportSecurityState);
        std::unique_ptr<MultiLogCTVerifier>     ct_verifier(new MultiLogCTVerifier());
        std::unique_ptr<net::CTPolicyEnforcer>  ct_policy_enforcer(new net::DefaultCTPolicyEnforcer());
        std::unique_ptr<quic::ProofVerifier>    proof_verifier;
        if (!verify_certificate) {
            proof_verifier.reset(new quic::BeQuicFakeProofVerifier());
        } else {
            proof_verifier.reset(new ProofVerifierChromium(
            cert_verifier.get(),
            ct_policy_enforcer.get(),
            transport_security_state.get(),
            ct_verifier.get()));
        }

        //Must create real client in this thread or tls object won't work.
        if (spdy_quic_client_ == NULL) {
            spdy_quic_client_.reset(new BeQuicSpdyClient(
                quic::QuicSocketAddress(ip_addr, port),
                serverId,
                versions,
                std::move(proof_verifier)));
        }

        //Set MTU.
        spdy_quic_client_->set_initial_max_packet_length(quic::kDefaultMaxPacketSize);

        //Initialize quic client.
        if (!spdy_quic_client_->Initialize()) {
            ret = kBeQuicErrorCode_Fatal_Error;
            LOG(ERROR) << "Failed to initialize bequic client." << std::endl;
            break;
        }

        //Do connecting and handshaking.
        if (!spdy_quic_client_->Connect()) {
            ret = kBeQuicErrorCode_Connect_Fail;
            quic::QuicErrorCode error = spdy_quic_client_->session()->error();
            LOG(ERROR) << "BeQuic connect error " << error << std::endl;
            break;
        }

        LOG(INFO) << "Connected!" << std::endl;

        //Causing invoke method out of block after connect and handshake finished.
        if (promise_) {
            promise_->set_value(ret);
            promise_.reset();
        }

        SpdyHeaderBlock header_block;
        header_block[":method"]      = method;
        header_block[":scheme"]      = gurl.scheme();
        header_block[":authority"]   = gurl.host();
        header_block[":path"]        = gurl.path();

        for (size_t i = 0; i < headers.size(); ++i) {
            InternalQuicHeader &header = headers[i];
            if (header.key.empty() || header.value.empty()) {
                continue;
            }  

            QuicStringPiece key     = header.key;
            QuicStringPiece value   = header.value; 
            quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&key);
            quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&value);
            header_block[key]       = value;
        }

        spdy_quic_client_->set_store_response(true);
        spdy_quic_client_->SendRequest(header_block, body, true);

        /*
        //For small file.
        spdy_quic_client_->SendRequestsAndWaitForResponse(header_block, body, true);
        size_t response_code         = spdy_quic_client_->latest_response_code();
        std::string response_body    = spdy_quic_client_->latest_response_body();

        LOG(INFO) << "Request:"     << std::endl;
        LOG(INFO) << "headers:"     << header_block.DebugString() << std::endl;
        LOG(INFO) << "Response:"    << response_code << std::endl;
        LOG(INFO) << "headers: "    << spdy_quic_client_->latest_response_headers() << std::endl;
        LOG(INFO) << "trailers: "   << spdy_quic_client_->latest_response_trailers() << std::endl;
        */
    } while (0);
    return ret;
}

}  // namespace net
