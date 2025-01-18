#include "channel.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

static pthread_t g_ch_thread;
static int       g_ch_running  = 0;
static int       g_channel     = 1;
static char      g_iface[64]   = {0};

static void* channel_thread_func(void *arg)
{
    while(g_ch_running) {
        // iwconfig 명령으로 채널 변경
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "iwconfig %s channel %d", g_iface, g_channel);
        system(cmd);

        // 다음 채널
        g_channel++;
        if(g_channel>13) g_channel=1;

        sleep(2); // 2초 후 다음 채널
    }
    return NULL;
}

void start_channel_hopping(const char *iface)
{
    strncpy(g_iface, iface, sizeof(g_iface)-1);
    g_ch_running = 1;
    g_channel = 1;
    pthread_create(&g_ch_thread, NULL, channel_thread_func, NULL);
}

void stop_channel_hopping()
{
    g_ch_running = 0;
    pthread_join(g_ch_thread, NULL);
}

int get_current_channel()
{
    return g_channel;
}
