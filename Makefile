CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap -lncurses
TARGET = dhcp-stats
SOURCE = main.c listfunc.c

# Default rule
all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LIBS)

pack:
	tar -cvf xlukas15.tar *

clean:
	rm -f $(TARGET)