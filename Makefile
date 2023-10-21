CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap -lncurses
TARGET = main
SOURCE = main.c listfunc.c

# Default rule
all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)