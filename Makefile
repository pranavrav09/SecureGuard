CC ?= cc
CPPFLAGS ?= -D_GNU_SOURCE -Iinclude
CFLAGS ?= -O2 -g -std=c17 -Wall -Wextra -Wpedantic -Werror -D_FORTIFY_SOURCE=2
LDFLAGS ?= -Wl,-z,relro,-z,now,-z,noexecstack

BIN_DIR := bin
BUILD_DIR := build
TARGET := $(BIN_DIR)/securerunner
SOURCES := src/main.c src/config.c src/util.c src/process.c src/seccomp.c src/cgroup.c src/container.c src/vm.c
OBJECTS := $(SOURCES:src/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean test test-process test-security fixture fixture-static guest-init install format check-linux

all: check-linux $(TARGET) fixture

check-linux:
	@test "$$(uname -s)" = Linux || { echo "SecureRunner builds on Linux (current OS: $$(uname -s))" >&2; exit 1; }

$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: src/%.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

fixture: $(BIN_DIR)/fixture

$(BIN_DIR)/fixture: tests/fixture.c | $(BIN_DIR)
	$(CC) $(CFLAGS) $< -o $@

fixture-static: check-linux | $(BIN_DIR)
	$(CC) $(CFLAGS) -static tests/fixture.c -o $(BIN_DIR)/fixture-static

guest-init: check-linux | $(BIN_DIR)
	$(CC) $(CFLAGS) -static vm/guest-init.c -o $(BIN_DIR)/securerunner-guest-init

$(BIN_DIR) $(BUILD_DIR):
	mkdir -p $@

test: test-process

test-process: all
	./tests/security.sh --process-only

test-security: all
	./tests/security.sh

install: all
	install -Dm0755 $(TARGET) $(DESTDIR)/usr/local/bin/securerunner

format:
	clang-format -i include/securerunner/*.h src/*.c tests/*.c vm/*.c

clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
