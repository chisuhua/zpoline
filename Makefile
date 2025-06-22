PROGS = libzpoline.so

CC = gcc

CLEANFILES = $(PROGS) *.o *.d

SRCDIR ?= ./

NO_MAN=
CFLAGS = -O0 -march=armv8-a -pipe
CFLAGS += -g -rdynamic
CFLAGS += -Werror -Wall -Wunused-function
CFLAGS += -Wextra
CFLAGS += -shared -fPIC
CFLAGS += -DSUPPLEMENTAL__REWRITTEN_ADDR_CHECK
CFLAGS += `pkg-config --cflags --libs glib-2.0`

LD_VERSION = $(shell ld --version | head -1 | grep -oP '[\d\.]+' | sed 's/\.//' | sed 's/\..*//' | head -1 )
# differentiate the code according to the library version
ifeq ($(shell test $(LD_VERSION) -ge 239; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_239
else ifeq ($(shell test $(LD_VERSION) -ge 229; echo $$?),0)
  CFLAGS += -DDIS_ASM_VER_229
endif

LDFLAGS += -lopcodes -ldl

C_SRCS = main_aarch64.c
OBJS = $(C_SRCS:.c=.o)

.PHONY: all
all: $(PROGS) hello libtestdl.so

$(PROGS): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lglib-2.0

hello.o: hello.c
	$(CC) -g  -c $^

hello: hello.o
	$(CC) -o $@ $^ -L. -lzpoline -Wl,-rpath,. -lglib-2.0

libtestdl.so: testdl.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)


clean:
	-@rm -rf $(CLEANFILES)
