#include "stdio.h"
#include "be_quic.h"
#include <string>

#ifdef WIN32
#include <windows.h>
#ifdef CHECK_MEMORY_LEAK
#define _CRTDBG_MAP_ALLOC
#include <cstdlib>
#include <crtdbg.h>
#endif
#endif

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

int main(int argc, char* argv[]) {
    while (1) {
        std::string g_data;
        TimeType t1 = GetTickCount();
        //https://10.18.18.57:443/bee/smv3qWPC0px7ofPdOf5WqSOloLvGoSYlsLrioLkmsWaWsWOWsLo7qLaFqmwBOWPBqUsdqLxioWPnNmcBqMK2ZM47fFoUgVPARMvANTs2qT4Avm8AoV8uytcigG2sY?play_sequence=1&play_time=1&ori=1&f=1&uid=qf
        //https://testlive.hd.sohu.com:443/xxx.mp4
        int handle = be_quic_open(
            "https://testlive.hd.sohu.com/2.mp4",
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
            5000,
            -1,
            -1);

        TimeType t2 = GetTickCount();

        printf("Open quic session %d, spent %I64u ms.\n", handle, t2 - t1);

        if (handle <= 0) {
            break;
        }

        if (g_write_file) {
            g_fp = fopen("1.mp4", "wb+");
        }

        auto buf = std::make_unique<unsigned char[]>(1024 * 1024);
        int len = (int)sizeof(buf);
        int total_len = 0;
        int read_len = 0;
        do {
            //break;
            read_len = be_quic_read(handle, buf.get(), len, 5000);
            if (read_len == 0) {
                continue;
            }

            if (read_len < 0) {
                break;
            }

            if (g_write_file) {
                //fwrite(buf, read_len, 1, g_fp);
            } else {
                g_data.append(std::string((char*)buf.get(), read_len));
            }
            total_len += read_len;
        } while (1);

        if (g_write_file) {
            fclose(g_fp);
            g_fp = NULL;
        }

        TimeType t3 = GetTickCount();
        TimeType dl_spend_ms = t3 - t2;
        double dl_spend_s = (double)dl_spend_ms / 1000;
        double speed = (double)total_len / (dl_spend_s * 1024);

        printf("Totally read data %d bytes using %lf s, speed %d KB/S.\n", total_len, dl_spend_s, (int)speed);
        if (!g_write_file) {
            printf("%s\n", g_data.c_str());
        }

        if (1) {
            BeQuicStats stats;
            memset(&stats, 0, sizeof(&stats));
            be_quic_get_stats(handle, &stats);
            printf("Stats:\n");
            printf("  packets_lost            : %I64d.\n", stats.packets_lost);
            printf("  packets_reordered       : %I64d.\n", stats.packets_reordered);
            printf("  rtt                     : %I64d ms.\n", stats.rtt / 1000);
            printf("  bandwidth               : %I64d kbps.\n", stats.bandwidth / 1024);
            printf("  resolve_time            : %I64d ms.\n", stats.resolve_time / 1000);
            printf("  connect_time            : %I64d ms.\n", stats.connect_time / 1000);
            printf("  first_data_receive_time : %I64d ms.\n", stats.first_data_receive_time / 1000);
        }

        while (0) {
            printf("Press ENTER to seek.\n");
            getchar();
            be_quic_seek(handle, 10 * 1024 * 1024, 0);
            printf("Press ENTER to read.\n");
            getchar();
            while (be_quic_read(handle, buf.get(), len, 0) > 0) {

            }
        }

        printf("Press ENTER to close.\n");

        getchar();

        be_quic_close(handle);

        printf("Closed quic session %d.\n", handle);
        //break;

        printf("Press ENTER to reopen.\n");
        getchar();
    }

    printf("Press ENTER to exit.\n");
    getchar();

#ifdef CHECK_MEMORY_LEAK
#ifdef WIN32
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_DEBUG);
    _CrtDumpMemoryLeaks();
#endif
#endif
    return 0;
}
