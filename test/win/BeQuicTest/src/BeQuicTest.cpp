#include "stdio.h"
#include "be_quic.h"
#include <string>

bool g_write_file   = true;
FILE *g_fp          = NULL;
std::string g_data;

int main(int argc, char* argv[]) {
    while (1) {
        int handle = be_quic_open(
            "https://www.example.org:6121",
            "GET",
            NULL,
            0,
            NULL,
            0,
            1,
            5000);

        printf("Open quic session %d.\n", handle);

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
            }
            else {
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
