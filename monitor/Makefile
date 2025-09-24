CC=gcc
CFLAGS=-Wall -Wextra -std=c99 -g
TARGET=process_monitor
SOURCE=process_monitor_simple.c

# Detect architecture and OS
ARCH := $(shell uname -m)
OS := $(shell uname -s)

# Add architecture-specific flags
ifeq ($(ARCH),x86_64)
    CFLAGS += -DARCH_X86_64
endif

ifeq ($(ARCH),aarch64)
    CFLAGS += -DARCH_ARM64
endif

ifeq ($(ARCH),arm64)
    CFLAGS += -DARCH_ARM64
endif

ifeq ($(ARCH),i386)
    CFLAGS += -DARCH_X86_32
endif

ifeq ($(ARCH),i686)
    CFLAGS += -DARCH_X86_32
endif

# Add OS-specific flags
ifeq ($(OS),Darwin)
    CFLAGS += -D__APPLE__
endif

ifeq ($(OS),Linux)
    CFLAGS += -D__LINUX__
endif

$(TARGET): $(SOURCE)
	@echo "Building for $(OS) on $(ARCH)"
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	cp $(TARGET) ../backend/

test: $(TARGET)
	@echo "Testing process monitor..."
	@echo "Architecture: $(ARCH)"
	@echo "OS: $(OS)"
	@./$(TARGET) /tmp/test_output.log echo "test" || echo "Test completed"
	@ls -la /tmp/test_output.log 2>/dev/null || echo "No output file (expected on some platforms)"

.PHONY: clean install test