#ifndef CHANNEL_H
#define CHANNEL_H

void start_channel_hopping(const char *iface);
void stop_channel_hopping();
int  get_current_channel();

#endif
