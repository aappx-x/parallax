# Makefile for PULSE/1 Maintenance Helper (pulse-helper)
# Compiles both vulnerable scenario artifact and hardened reference binaries.

CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c99
HARDENED_CFLAGS ?= $(CFLAGS) -DFIXED_MODE -fstack-protector-strong -D_FORTIFY_SOURCE=2
DESTDIR ?=
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

TARGET_VULN = pulse-helper
TARGET_FIXED = pulse-helper-fixed
SRC = pulse-helper.c

.PHONY: all clean install install-fixed

all: $(TARGET_VULN) $(TARGET_FIXED)

$(TARGET_VULN): $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

$(TARGET_FIXED): $(SRC)
	$(CC) $(HARDENED_CFLAGS) -o $@ $(SRC)

install: $(TARGET_VULN)
	install -d $(DESTDIR)$(BINDIR)
	install -m 4750 $(TARGET_VULN) $(DESTDIR)$(BINDIR)/$(TARGET_VULN)

install-fixed: $(TARGET_FIXED)
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(TARGET_FIXED) $(DESTDIR)$(BINDIR)/$(TARGET_FIXED)

clean:
	rm -f $(TARGET_VULN) $(TARGET_FIXED) *.o
