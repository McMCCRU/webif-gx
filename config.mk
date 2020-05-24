CC = /opt/goxceed/csky-linux-tools-i386-uclibc-20170724/bin/csky-linux-gcc
# CC = /opt/goxceed/csky-linux/bin/csky-linux-gcc
# CC = gcc
SOURCES = $(PROG).c pt.c mongoose.c
CFLAGS = -g -W -Wall -Werror -I./ -Wno-unused-function $(CFLAGS_EXTRA) $(MODULE_CFLAGS) -Wno-format-truncation

all: $(PROG)

CFLAGS += -pthread -ldl

ifeq ($(SSL_LIB),openssl)
CFLAGS += -DMG_ENABLE_SSL -lssl -lcrypto
endif
ifeq ($(SSL_LIB),mbedtls)
CFLAGS += -DMG_ENABLE_SSL -DMG_SSL_IF=MG_SSL_IF_MBEDTLS -DMG_SSL_MBED_DUMMY_RANDOM -lmbedcrypto -lmbedtls -lmbedx509
endif

$(PROG): $(SOURCES)
	$(CC) $(SOURCES) -s -o $@ $(CFLAGS)

clean:
	rm -rf *.gc* *.dSYM *.exe *.obj *.o a.out $(PROG)
