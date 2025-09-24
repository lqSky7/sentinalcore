CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -g
TARGET=test_malware
SOURCE=test_malware.c

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

test: $(TARGET)
	./$(TARGET)

.PHONY: clean test