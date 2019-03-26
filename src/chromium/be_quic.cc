#include "net/tools/quic/be_quic.h"
#include "net/tools/quic/be_quic_client_manager.h"
#include "net/tools/quic/be_quic_fake_proof_verifier.h"
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/task/task_scheduler/task_scheduler.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/crypto/proof_verifier_chromium.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"
#include "net/third_party/quiche/src/spdy/core/spdy_header_block.h"
#include "net/tools/quic/quic_simple_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
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

//External log callback set by be_quic_set_log_callback method.
BeQuicLogCallback g_external_log_callback = NULL;

//Hook internal log.
bool internal_log_callback(int severity, const char* file, int line, size_t message_start, const std::string& str) {
    const char *severities[logging::LOG_NUM_SEVERITIES + 1] = {
        "Verbose",
        "Info",
        "Warning",
        "Error",
        "Fatal"
    };

    std::string msg = std::string(str.c_str() + message_start);
    if (g_external_log_callback != NULL) {
        g_external_log_callback(severities[severity + 1], file, line, msg.c_str());
    } else {
        printf("[%s][%s:%d] %s", severities[severity + 1], file, line, msg.c_str());
    }

    return true;
}

////////////////////////////////////Exports methods implementation//////////////////////////////////////
int BE_QUIC_CALL be_quic_open(
    const char *url,
    const char *method,
    BeQuicHeader *headers,
    int headers_count,
    const char *body,
    int body_size,
    int verify_certificate) {
    int ret = kBeQuicErrorCode_Success;
    do {
        static bool first_invoke = true;
        if (first_invoke) {
            //Setup logging.
            logging::LoggingSettings settings;
            settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
            CHECK(logging::InitLogging(settings));
            logging::SetLogMessageHandler(internal_log_callback);

            //Startup TaskScheduler.
            base::TaskScheduler::CreateAndStartWithDefaultParams("be_quic");

            first_invoke = false;
            LOG(INFO) << "BeQuic 1.0" << std::endl;
        }

        //Local message loop.
        base::AtExitManager exit_manager;
        base::MessageLoopForIO message_loop;

        //Check method.
        std::string method_str = (method == NULL) ? "GET" : std::string(method);
        if (strncmp(method_str.c_str(), "GET", method_str.size()) != 0 && 
            strncmp(method_str.c_str(), "POST", method_str.size()) != 0) {
            ret = kBeQuicErrorCode_Invalid_Method;
            break;
        }

        //Check url.
        if (url == NULL) {
            ret = kBeQuicErrorCode_Invalid_Url;
            break;
        }

        //Parse host and port from url.
        GURL gurl(url);
        std::string host    = gurl.host();
        int port            = gurl.EffectiveIntPort();
        
        LOG(INFO) << "BeQuicOpen " << host << ":" << port << " => " << url << "," << method_str << std::endl;

        //Resolve host to address synchronously.
        net::AddressList addresses;
        if (net::SynchronousHostResolver::Resolve(host, &addresses) != net::OK) {
            ret = kBeQuicErrorCode_Resolve_Fail;
            break;
        }
        
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
        if (verify_certificate) {
            proof_verifier.reset(new quic::BeQuicFakeProofVerifier());
        } else {
            proof_verifier.reset(new ProofVerifierChromium(
            cert_verifier.get(),
            ct_policy_enforcer.get(),
            transport_security_state.get(),
            ct_verifier.get()));
        }
        
        //Create BeQuic client.
        net::BeQuicClient::Ptr client = net::BeQuicClientManager::instance()->create_client(
            quic::QuicSocketAddress(ip_addr, port),
            serverId,
            versions,
            std::move(proof_verifier));
        if (client == NULL) {
            ret = kBeQuicErrorCode_Fatal_Error;
            break;
        } else {
            ret = client->get_handle();
        }

        //Connect & handshake synchronously.
        if (!client->Connect()) {
            quic::QuicErrorCode error = client->session()->error();
            LOG(ERROR) << "BeQuic connect error " << error << std::endl;
            ret = kBeQuicErrorCode_Connect_Fail;
            break;
        }

        SpdyHeaderBlock header_block;
        header_block[":method"]      = method;
        header_block[":scheme"]      = gurl.scheme();
        header_block[":authority"]   = gurl.host();
        header_block[":path"]        = gurl.path();
        
        if (headers != NULL && headers_count > 0) {
            for (int i = 0; i < headers_count; ++i) {
                BeQuicHeader &header = headers[i];
                if (header.key == NULL || header.value == NULL) {
                    continue;
                }  

                QuicStringPiece key = header.key;
                QuicStringPiece value = header.value; 
                quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&key);
                quic::QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&value);
                header_block[key] = value;
            }
        }

        std::string body_str = (body == NULL) ? std::string("") : std::string(body, body_size);
        client->set_store_response(true);
        client->SendRequestAndWaitForResponse(header_block, body_str, true);

        size_t response_code         = client->latest_response_code();
        std::string response_body    = client->latest_response_body();

        LOG(INFO) << "Request:"     << std::endl;
        LOG(INFO) << "headers:"     << header_block.DebugString() << std::endl;
        LOG(INFO) << "Response:"    << response_code << std::endl;
        LOG(INFO) << "headers: "    << client->latest_response_headers() << std::endl;
        LOG(INFO) << "body: "       << response_body << std::endl;
        LOG(INFO) << "trailers: "   << client->latest_response_trailers() << std::endl;
    } while (0);    
    return ret;
}

int BE_QUIC_CALL be_quic_close(int handle) {
    net::BeQuicClientManager::instance()->release_client(handle);
    return 0;
}

int BE_QUIC_CALL be_quic_read(int handle, unsigned char *buf, int size) {
    return 0;
}

int BE_QUIC_CALL be_quic_write(int handle, const unsigned char *buf, int size) {
    return 0;
}

void BE_QUIC_CALL be_quic_set_log_callback(BeQuicLogCallback callback) {
    g_external_log_callback = callback;
}

// int BE_QUIC_CALL be_quic_seek(int handle, int64_t off, int whence) {
//     return 0;
// }
