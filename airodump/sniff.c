#include "sniff.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>

// Radiotap/802.11 헤더 (간단 버전)
#pragma pack(push,1)
typedef struct {
    uint8_t  revision;
    uint8_t  pad;
    uint16_t length;
    uint32_t present;
    // 실제로는 가변
} radiotap_hdr;

typedef struct {
    uint16_t frame_control;
    uint16_t duration;
    uint8_t  addr1[6];
    uint8_t  addr2[6];
    uint8_t  addr3[6];
    uint16_t seq_ctrl;
} ieee80211_hdr;
#pragma pack(pop)

// frame control 매크로
#define FC_TYPE(fc)    ( ((fc) & 0x000c) >> 2 )   // 2비트, 0=mgt,1=ctrl,2=data
#define FC_SUBTYPE(fc) ( ((fc) & 0x00f0) >> 4 )

// 전역(정확히는 static) 배열
static APInfo      g_ap_list[MAX_AP];
static int         g_ap_count = 0;

static StationInfo g_st_list[MAX_STATION];
static int         g_st_count = 0;

static pcap_t     *g_handle = NULL;

//------------------------------------------------------------------------------
// AP/Station 검색 & 추가 함수
//------------------------------------------------------------------------------
static int find_ap_index(const uint8_t *bssid)
{
    for(int i=0; i<g_ap_count; i++){
        if(memcmp(g_ap_list[i].bssid, bssid, 6)==0) {
            return i;
        }
    }
    return -1;
}
static int add_ap(const uint8_t *bssid)
{
    if(g_ap_count >= MAX_AP) return -1;
    int idx = g_ap_count++;
    APInfo *ap = &g_ap_list[idx];
    memset(ap, 0, sizeof(APInfo));
    memcpy(ap->bssid, bssid, 6);
    ap->pwr = -99;
    strcpy(ap->enc,"OPN");    // 기본값
    strcpy(ap->cipher,"-");
    strcpy(ap->auth,"-");
    ap->found = 1;
    return idx;
}

static int find_station_index(const uint8_t *bssid, const uint8_t *st)
{
    for(int i=0; i<g_st_count; i++){
        if( (memcmp(g_st_list[i].station, st,6)==0) &&
            (memcmp(g_st_list[i].bssid,   bssid,6)==0) ) {
            return i;
        }
    }
    return -1;
}
static int add_station(const uint8_t *bssid, const uint8_t *st)
{
    if(g_st_count >= MAX_STATION) return -1;
    int idx = g_st_count++;
    StationInfo *si = &g_st_list[idx];
    memset(si, 0, sizeof(StationInfo));
    memcpy(si->bssid, bssid, 6);
    memcpy(si->station, st, 6);
    si->pwr = -99;
    si->rate = 1;
    si->found = 1;
    return idx;
}

//------------------------------------------------------------------------------
// 태그 파싱 (ESSID, DS Parameter(채널) 등)
// 실제 airodump-ng 수준으로 하려면 RSN/WPA IE도 파싱해야 함
//------------------------------------------------------------------------------
static void parse_tagged_params(const uint8_t *buf, int len, APInfo *ap)
{
    int pos = 0;
    while(pos + 2 <= len) {
        uint8_t tag_num = buf[pos];
        uint8_t tag_len = buf[pos+1];
        const uint8_t *tag_data = &buf[pos+2];
        if(pos + 2 + tag_len > len) break;

        // ESSID
        if(tag_num == 0) {
            int copy_len = (tag_len < ESSID_LEN)? tag_len : ESSID_LEN;
            memcpy(ap->essid, tag_data, copy_len);
            ap->essid[copy_len] = '\0';
        }
        // DS Parameter Set -> 채널
        else if(tag_num == 3 && tag_len == 1) {
            ap->channel = tag_data[0];
        }

        // RSN/WPA(0x30,0xDD) 등은 생략
        pos += (2 + tag_len);
    }
}

//------------------------------------------------------------------------------
// 단순 RSSI 추출 (radiotap_len 바이트 바로 뒤를 RSSI로 가정)
// 실제로는 radiotap present 비트맵을 분석해야 함
//------------------------------------------------------------------------------
static int8_t get_rssi(const uint8_t *packet, int total_len)
{
    // radiotap_hdr* rh = (radiotap_hdr*)packet;  // 필요시 해석
    // 여기서는 그냥 packet[rh->length] 위치값을 리턴
    if(total_len < 20) return -99;
    // 대충 18~20번째 바이트쯤에 RSSI가 들어온다고 가정(데모)
    return (int8_t) packet[18];
}

//------------------------------------------------------------------------------
// 패킷 콜백
//------------------------------------------------------------------------------
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    if(h->len < sizeof(radiotap_hdr) + sizeof(ieee80211_hdr)) return;
    radiotap_hdr  *rh  = (radiotap_hdr*)bytes;
    int radiotap_len   = rh->length;
    if(radiotap_len > h->len) return;

    ieee80211_hdr *hdr = (ieee80211_hdr*)(bytes + radiotap_len);
    uint16_t fc  = hdr->frame_control;
    uint8_t  type   = FC_TYPE(fc);
    uint8_t  stype  = FC_SUBTYPE(fc);

    int8_t rssi = get_rssi(bytes, h->len);

    // Management: Beacon/ProbeResp
    if(type == 0) {
        if(stype == 8 /*Beacon*/ || stype == 5 /*ProbeResp*/) {
            uint8_t bssid[6];
            memcpy(bssid, hdr->addr2, 6);
            int idx = find_ap_index(bssid);
            if(idx<0) {
                idx = add_ap(bssid);
                if(idx<0) return;
            }
            APInfo *ap = &g_ap_list[idx];
            ap->pwr = rssi;
            if(stype == 8) {
                ap->beacon_count++;
            }
            // Tagged Params
            const uint8_t *mgmt_fixed = (uint8_t*)(hdr+1);
            // 12바이트( timestamp(8)+beacon interval(2)+capability(2) )
            const uint8_t *tag_start = mgmt_fixed + 12;
            int tag_len = (bytes + h->len) - tag_start;
            if(tag_len>0) {
                parse_tagged_params(tag_start, tag_len, ap);
            }
        }
    }
    // Data
    else if(type == 2) {
        // 간단히 addr2=sta, addr1=bssid 라고 가정(To DS=1,From DS=0 고려 x)
        uint8_t st_mac[6], bssid[6];
        memcpy(st_mac, hdr->addr2, 6);
        memcpy(bssid,  hdr->addr1, 6);

        int ap_idx = find_ap_index(bssid);
        if(ap_idx<0) {
            ap_idx = add_ap(bssid);
        }
        if(ap_idx>=0) {
            g_ap_list[ap_idx].data_count++;
        }

        int st_idx = find_station_index(bssid, st_mac);
        if(st_idx<0) {
            st_idx = add_station(bssid, st_mac);
        }
        if(st_idx>=0) {
            g_st_list[st_idx].frames++;
            g_st_list[st_idx].pwr = rssi;
        }
    }
}

//------------------------------------------------------------------------------
// 외부 호출: 매번 pcap_dispatch()로 패킷 처리
//------------------------------------------------------------------------------
void sniff_nonblock_once()
{
    if(!g_handle) return;
    pcap_dispatch(g_handle, 100, packet_handler, NULL);
}

//------------------------------------------------------------------------------
// pcap 열기 (논블록)
//------------------------------------------------------------------------------
void init_sniffer(const char *iface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(iface, BUFSIZ, 1, 100, errbuf);
    if(!g_handle) {
        fprintf(stderr, "pcap_open_live() 실패: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }
    if(pcap_setnonblock(g_handle, 1, errbuf)==-1) {
        fprintf(stderr, "pcap_setnonblock() 실패: %s\n", errbuf);
        pcap_close(g_handle);
        g_handle = NULL;
        exit(EXIT_FAILURE);
    }
    // 간단 필터: type mgt or type data
    struct bpf_program fp;
    char filter_exp[] = "(type mgt) or (type data)";
    if(pcap_compile(g_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN)==-1) {
        fprintf(stderr, "pcap_compile() 실패\n");
        pcap_close(g_handle);
        g_handle = NULL;
        exit(EXIT_FAILURE);
    }
    if(pcap_setfilter(g_handle, &fp)==-1) {
        fprintf(stderr, "pcap_setfilter() 실패\n");
        pcap_freecode(&fp);
        pcap_close(g_handle);
        g_handle = NULL;
        exit(EXIT_FAILURE);
    }
    pcap_freecode(&fp);

    // 배열 초기화
    memset(g_ap_list, 0, sizeof(g_ap_list));
    g_ap_count = 0;
    memset(g_st_list, 0, sizeof(g_st_list));
    g_st_count = 0;
}

void close_sniffer()
{
    if(g_handle) {
        pcap_close(g_handle);
        g_handle = NULL;
    }
}

//------------------------------------------------------------------------------
// AP/Station 목록 접근자
//------------------------------------------------------------------------------
int get_ap_count()
{
    return g_ap_count;
}
APInfo* get_ap_info(int idx)
{
    if(idx<0 || idx>=g_ap_count) return NULL;
    return &g_ap_list[idx];
}

int get_station_count()
{
    return g_st_count;
}
StationInfo* get_station_info(int idx)
{
    if(idx<0 || idx>=g_st_count) return NULL;
    return &g_st_list[idx];
}
