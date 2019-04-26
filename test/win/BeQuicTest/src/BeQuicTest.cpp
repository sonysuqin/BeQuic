#include "stdio.h"
#include "be_quic.h"
#include <string>

#include <windows.h>

typedef uint64_t TimeType;

static TimeType get_tickcount() {
#ifdef WIN32
    //return ::GetTickCount();
    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (1000000L * counter.QuadPart / freq.QuadPart) / 1000L;
#elif defined ANDROID
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * (TimeType)1000 + ts.tv_nsec / 1000000;
#elif defined __IOS__
    mach_timebase_info_data_t mach_info;
    mach_timebase_info(&mach_info);
    double factor = static_cast<double>(mach_info.numer) / mach_info.denom;
    return (mach_absolute_time() * factor) / 1000000L;
#elif defined _LINUX_
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * (TimeType)1000 + ts.tv_nsec / 1000000;
#else 
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec * (TimeType)1000 + tv.tv_usec / 1000;
#endif
}

bool g_write_file   = true;
FILE *g_fp          = NULL;
std::string g_data;

int main(int argc, char* argv[]) {
    while (1) {
        TimeType t1 = GetTickCount();
        int handle = be_quic_open(
            "https://www.example.org:6121",
            NULL,
            0,
            "GET",
            NULL,
            0,
            NULL,
            0,
            1,
            -1,
            kBeQuic_Handshake_Protocol_Quic_Crypto,
            43,
            5000);

        TimeType t2 = GetTickCount();

        printf("Open quic session %d, spent %I64u ms.\n", handle, t2 - t1);

        if (handle <= 0) {
            break;
        }

        if (g_write_file) {
            g_fp = fopen("1.mp4", "wb+");
        }

        unsigned char buf[32 * 1024] = { 0 };
        int len = (int)sizeof(buf);
        int total_len = 0;
        int read_len = 0;
        do {
            read_len = be_quic_read(handle, buf, len, 5000);
            if (read_len == 0) {
                continue;
            }

            if (read_len < 0) {
                break;
            }

            if (g_write_file) {
                fwrite(buf, read_len, 1, g_fp);
            } else {
                g_data.append(std::string((char*)buf, read_len));
            }
            total_len += read_len;
        } while (1);

        if (g_write_file) {
            fclose(g_fp);
        }

        printf("Totally read data %d bytes.\n", total_len);
        if (!g_write_file) {
            printf("%s\n", g_data.c_str());
        }

        printf("Press ENTER to close.\n");

        getchar();

        be_quic_close(handle);

        printf("Closed quic session %d.\n", handle);
        printf("Press ENTER to open again.\n");

        getchar();
    }

    getchar();
    return 0;
}
