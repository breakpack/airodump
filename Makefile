CC = gcc
CFLAGS = -g -Wall
TARGET = airodump

OBJS = main.o sniff.o channel.o display.o

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) -lpcap -lncurses

main.o: main.c sniff.h channel.h display.h
	$(CC) $(CFLAGS) -c main.c

sniff.o: sniff.c sniff.h
	$(CC) $(CFLAGS) -c sniff.c

channel.o: channel.c channel.h
	$(CC) $(CFLAGS) -c channel.c

display.o: display.c display.h sniff.h channel.h
	$(CC) $(CFLAGS) -c display.c

clean:
	rm -f *.o $(TARGET)
