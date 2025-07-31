# Copyright 2018 osMUD

# Global target
all: osmud

CC = gcc
CFLAGS = -Wall -g -std=c99 -D_XOPEN_SOURCE=600 -DDEBUG \
         $(shell pkg-config --cflags libmicrohttpd)
LDFLAGS = -ljson-c -lcurl -pthread -lpthread -lcrypto \
          $(shell pkg-config --libs libmicrohttpd)
CFLAGSCONF = `pkg-config --cflags glib-2.0`
LDFLAGSCONF = `pkg-config --libs glib-2.0`
RULES_DIR = rules
ODIR = odir

DEPS = $(wildcard *.h)
SRC = $(wildcard *.c)
OBJ = $(patsubst %.c, %.o, $(SRC))

version.c:
	git rev-parse HEAD | awk ' BEGIN {print "#include \"version.h\""} {print "const char * build_git_sha = \"" $$0"\";"} END {}' > version.c
	date | awk 'BEGIN {} {print "const char * build_git_time = \""$$0"\";"} END {} ' >> version.c 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

openwrt.o: openwrt/openwrt.c
	$(CC) $(CFLAGS) -c -o openwrt.o openwrt/openwrt.c

config.o: etc/interface_conf_parser.c
	$(CC) $(CFLAGSCONF) -c etc/interface_conf_parser.c -o config.o

linux.o: config.o router-machine/linux.c
	$(CC) $(CFLAGS) $(CFLAGSCONF) -c router-machine/linux.c -o linux.o

x509_server.o: x509_server.c
	$(CC) $(CFLAGS) -c -o x509_server.o x509_server.c

osmud: osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o openwrt.o mudparser.o mud_manager.o version.o x509_server.o
	$(CC) $(CFLAGS) $(LDFLAGS) osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o openwrt.o mudparser.o mud_manager.o version.o x509_server.o -o osmud

osmud-generic: osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o config.o linux.o mudparser.o mud_manager.o version.o x509_server.o
	@mkdir -p $(RULES_DIR)
	$(CC) $(CFLAGS) $(CFLAGSCONF) osmud.o comms.o oms_utils.o oms_logging.o dhcp_event.o config.o linux.o mudparser.o mud_manager.o version.o x509_server.o -o osmud $(LDFLAGS) $(LDFLAGSCONF)

.PHONY: clean

clean:
	rm -f osmud *.o version.c

