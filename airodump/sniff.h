#ifndef SNIFF_H
#define SNIFF_H

#include <stdint.h>

#define MAX_AP       1024
#define MAX_STATION  2048
#define ESSID_LEN    32

// AP 정보 구조
typedef struct {
    uint8_t bssid[6];
    char    essid[ESSID_LEN+1];
    int     pwr;             // 신호 세기(dBm)
    int     beacon_count;
    int     data_count;
    int     channel;

    // 간단히 암호화 관련 문자열만 저장
    char    enc[8];          // 예: "WPA2", "WEP", "OPN"
    char    cipher[8];       // 예: "CCMP", "TKIP", "-"
    char    auth[8];         // 예: "PSK", "MGT", "-"

    int     found;
} APInfo;

// 스테이션(클라이언트) 정보 구조
typedef struct {
    uint8_t bssid[6];    // 연결된 AP의 BSSID (또는 not associated)
    uint8_t station[6];  // 스테이션 MAC

    int     pwr;
    int     rate;        // 단순 표시용
    int     lost;        // 패킷 손실 추정
    int     frames;      // 전송/수신 프레임 수

    char    notes[16];
    char    probes[64];

    int     found;
} StationInfo;

// pcap 초기화 & 종료
void init_sniffer(const char *iface);
void close_sniffer();

// 논블록 스니핑(매 프레임마다 호출)
void sniff_nonblock_once();

// AP/Station 목록 접근자
int      get_ap_count();
APInfo*  get_ap_info(int idx);

int          get_station_count();
StationInfo* get_station_info(int idx);

#endif
