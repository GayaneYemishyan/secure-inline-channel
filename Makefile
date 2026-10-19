# secure-inline-channel: build automation
#
#   make              build ./secure-channel
#   make SAN=1        build with AddressSanitizer + UBSan (run `make clean` first)
#   make test         build and run tests/test_*.c (if any)
#   make psk          create psk.key if it does not exist
#   make clean        remove build output and the binary (keeps psk.key)

# Recipe lines start with ">" instead of a TAB, so copy/paste cannot break them.
.RECIPEPREFIX = >

CC      ?= gcc
TARGET  := secure-channel

CFLAGS  ?= -O2 -g
CFLAGS  += -std=gnu11 -Wall -Wextra -Iinclude
LDFLAGS ?=

ifeq ($(SAN),1)
CFLAGS  += -O0 -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS += -fsanitize=address,undefined
endif

# Libraries: pkg-config when available, plain flags otherwise.
PKG_CFLAGS := $(shell pkg-config --cflags libnetfilter_queue libcrypto 2>/dev/null)
PKG_LIBS   := $(shell pkg-config --libs   libnetfilter_queue libcrypto 2>/dev/null)
ifeq ($(strip $(PKG_LIBS)),)
PKG_LIBS := -lnetfilter_queue -lcrypto
endif
CFLAGS += $(PKG_CFLAGS)
LDLIBS := $(PKG_LIBS) -pthread

SRCS     := $(wildcard src/*.c)
OBJS     := $(SRCS:src/%.c=build/%.o)
LIB_OBJS := (filter-outbuild/main.o,(OBJS))     # everything except main()

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:tests/%.c=build/tests/%)

.PHONY: all clean test psk help

all: $(TARGET)

$(TARGET): $(OBJS)
> $(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)
> @echo "built ./$(TARGET)"

# -MMD/-MP write .d files, so editing a header rebuilds what depends on it.
build/%.o: src/%.c | build
> $(CC) $(CFLAGS) -MMD -MP -c $< -o $@

build build/tests:
> mkdir -p $@

# Each tests/test_*.c is its own program, linked with every module except main.c.
build/tests/%: tests/%.c $(LIB_OBJS) | build/tests
> $(CC) $(CFLAGS) $(LDFLAGS) -MMD -MP $< $(LIB_OBJS) -o $@ $(LDLIBS)

test: $(TEST_BINS)
> @[ -n "$(TEST_BINS)" ] || echo "no tests found in tests/"
> @for t in $(TEST_BINS); do echo "==
t";./
t || exit 1; done

psk:
> @[ -f psk.key ] && echo "psk.key already exists" || \
>   (openssl rand -hex 32 > psk.key && chmod 600 psk.key && echo "created psk.key")

clean:
> rm -rf build $(TARGET)

help:
> @sed -n '3,8p' Makefile

-include $(OBJS:.o=.d) $(TEST_BINS:=.d)

