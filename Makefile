CC = gcc
CFLAGS = -Wall -g
LIBS = -lpcap
TARGET = main
SOURCE = main.c

# Default rule
all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)