CC = clang

OPENSSL_DIR =

SRCDIR = src
INCDIR = include
VPATH = $(SRCDIR)

CFLAGS = -g -Wall -Wextra -std=c17 -maes -I$(INCDIR)
LDFLAGS =
LDLIBS = -lssl -lcrypto -lrt

ifneq ($(OPENSSL_DIR),)
    CFLAGS += -I$(OPENSSL_DIR)/include
    LDFLAGS += -L$(OPENSSL_DIR)/lib
endif

COMMON_SRCS = aes_sw.c aes_core.c t_aes_sw.c utils.c t_aes_ni.c aes_ni_core.c speed_helper.c
TARGET_SRCS = encrypt.c decrypt.c speed.c stat.c

TARGETS = $(TARGET_SRCS:.c=)
COMMON_OBJS = $(COMMON_SRCS:.c=.o)

.PHONY: all clean

all: $(TARGETS)

$(TARGETS): %: %.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(TARGETS) *.o
