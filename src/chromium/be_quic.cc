#include "net/tools/quic/be_quic.h"
#include "net/tools/quic/be_quic_client_manager.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/task/task_scheduler/task_scheduler.h"

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

////////////////////////////////////Export methods implementation//////////////////////////////////////
int BE_QUIC_CALL be_quic_open(
    const char *url,
    const char *ip,
    unsigned short port,
    const char *method,
    BeQuicHeader *headers,
    int header_num,
    const char *body,
    int body_size,
    int verify_certificate,
    int timeout) {
    int ret = kBeQuicErrorCode_Success;
    do {
        static bool first_invoke = true;
        if (first_invoke) {
            //Setup commanline.
            int argc = 1;
            const char *argv[1] = {"BeQuic"};
            base::CommandLine::Init(argc, argv);

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
        
        //Create BeQuic client.
        net::BeQuicClient::Ptr client = net::BeQuicClientManager::instance()->create_client();
        if (client == NULL) {
            ret = kBeQuicErrorCode_Fatal_Error;
            break;
        } else {
            ret = client->get_handle();
        }

        //Save headers.
        std::vector<net::InternalQuicHeader> header_vec;
        if (headers != NULL && header_num > 0) {
            for (int i = 0; i < header_num; ++i) {
                BeQuicHeader &header = headers[i];
                if (header.key != NULL && header.value != NULL) {
                    header_vec.emplace_back(header.key, header.value);
                }
            }
        }

        //Save body.
        std::string body_str = (body == NULL) ? std::string("") : std::string(body, body_size);

        //Request, will create a new thread.
        int rv = client->open(
            url,
            ip,
            port,
            method_str,
            header_vec,
            body_str,
            (verify_certificate <= 0) ? true : false,
            timeout);
        if (rv != kBeQuicErrorCode_Success) {
            net::BeQuicClientManager::instance()->close_and_release_client(ret);
            ret = rv;
            break;
        }
    } while (0);
    return ret;
}

int BE_QUIC_CALL be_quic_close(int handle) {
    net::BeQuicClientManager::instance()->close_and_release_client(handle);
    return 0;
}

int BE_QUIC_CALL be_quic_read(int handle, unsigned char *buf, int size, int timeout) {
    int ret = 0;
    do {
        net::BeQuicClient::Ptr client = net::BeQuicClientManager::instance()->get_client(handle);
        if (client == NULL) {
            ret = kBeQuicErrorCode_Not_Found;
            break;
        }

        ret = client->read_body(buf, size, timeout);
    } while (0);
    return ret;
}

int BE_QUIC_CALL be_quic_write(int handle, const unsigned char *buf, int size) {
    return 0;
}

bequic_int64_t BE_QUIC_CALL be_quic_seek(int handle, bequic_int64_t off, int whence) {
    bequic_int64_t ret = 0;
    do {
        net::BeQuicClient::Ptr client = net::BeQuicClientManager::instance()->get_client(handle);
        if (client == NULL) {
            ret = kBeQuicErrorCode_Not_Found;
            break;
        }

        ret = client->seek(off, whence);
    } while (0);
    return ret;
}

void BE_QUIC_CALL be_quic_set_log_callback(BeQuicLogCallback callback) {
    g_external_log_callback = callback;
}
