#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <ncurses.h>

#include "sniff.h"
#include "channel.h"
#include "display.h"

static int g_running = 1;

// 시그널 핸들러(Ctrl+C)
static void handle_signal(int sig)
{
    g_running = 0;
}

int main(int argc, char *argv[])
{
    if(argc < 2) {
        printf("사용법: %s <monitor_interface>\n", argv[0]);
        return 0;
    }

    // Ctrl+C 시 종료
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // 1) pcap(sniffer) 초기화
    init_sniffer(argv[1]);

    // 2) 채널 호핑 시작 (쓰레드)
    start_channel_hopping(argv[1]);

    // 3) ncurses 초기화
    init_display();

    // 4) 메인 루프
    while(g_running) {
        // 패킷 처리
        sniff_nonblock_once();

        // 화면 갱신
        render_screen();

        // 키 입력(q면 종료)
        int ch = getch();
        if(ch == 'q' || ch=='Q') {
            g_running = 0;
            break;
        }
        usleep(200000); // 0.2초
    }

    // 5) clean up
    close_display();        // ncurses 종료
    stop_channel_hopping(); // 채널 호핑 스레드 종료
    close_sniffer();        // pcap 종료

    printf("[*] 종료되었습니다.\n");
    return 0;
}
