#include "display.h"
#include <ncurses.h>
#include <string.h>
#include <time.h>
#include "sniff.h"
#include "channel.h"

// 시작 시간 기록용
static time_t g_start_time = 0;

// 외부에서 호출
void init_display()
{
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    nodelay(stdscr, TRUE); 
    keypad(stdscr, TRUE);

    g_start_time = time(NULL);
}

void close_display()
{
    endwin();
}

// 화면 그리기
void render_screen()
{
    erase();

    // 상단 상태줄
    time_t now = time(NULL);
    int elapsed = (int) difftime(now, g_start_time);
    int ch = get_current_channel();
    mvprintw(0,0, "CH %2d ][ Elapsed: %2d s ][ %s",
             ch, elapsed, "airodump_like demo");

    // AP 리스트 헤더
    mvprintw(2,0, "BSSID              PWR  Beacons  #Data  CH   ENC   CIPHER AUTH  ESSID");

    int y = 3;
    int ap_count = get_ap_count();
    for(int i=0; i<ap_count; i++){
        if(y >= LINES-5) break; // 화면이 꽉 차면 중단
        APInfo *ap = get_ap_info(i);
        if(!ap) continue;

        mvprintw(y, 0,  "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap->bssid[0],ap->bssid[1],ap->bssid[2],
                 ap->bssid[3],ap->bssid[4],ap->bssid[5]);
        mvprintw(y,19, "%4d", ap->pwr);
        mvprintw(y,25, "%7d", ap->beacon_count);
        mvprintw(y,33, "%6d", ap->data_count);
        mvprintw(y,40, "%3d", ap->channel);
        mvprintw(y,44, "%5s", ap->enc);
        mvprintw(y,50, "%6s", ap->cipher);
        mvprintw(y,57, "%4s", ap->auth);
        mvprintw(y,62, " %s", ap->essid[0]? ap->essid : "<hidden>");

        y++;
    }

    // 스테이션 리스트 헤더
    mvprintw(y+1,0," BSSID              STATION            PWR  Rate  Lost  Frames  Probes");
    y+=2;
    int st_count = get_station_count();
    for(int i=0; i<st_count; i++){
        if(y >= LINES-1) break;
        StationInfo *st = get_station_info(i);

        // BSSID
        if(memcmp(st->bssid,"\x00\x00\x00\x00\x00\x00",6)==0) {
            mvprintw(y,1, "(not associated) ");
        } else {
            mvprintw(y,1, "%02X:%02X:%02X:%02X:%02X:%02X",
                     st->bssid[0],st->bssid[1],st->bssid[2],
                     st->bssid[3],st->bssid[4],st->bssid[5]);
        }

        // STATION
        mvprintw(y,19, "%02X:%02X:%02X:%02X:%02X:%02X",
                 st->station[0],st->station[1],st->station[2],
                 st->station[3],st->station[4],st->station[5]);

        // PWR
        mvprintw(y,38, "%4d", st->pwr);

        // Rate
        mvprintw(y,44, "%4d", st->rate);

        // Lost
        mvprintw(y,49, "%5d", st->lost);

        // Frames
        mvprintw(y,55, "%7d", st->frames);

        // Probes
        mvprintw(y,64, "%s", st->probes);

        y++;
    }

    refresh();
}
