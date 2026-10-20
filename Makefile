SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
LIB_OBJS = $(filter-out rndaddr.o, $(SRCS:.c=.o))
PROG_OBJS = rndaddr.o
LDSO_OBJS = randsaddr.lo shim.lo prng.lo
override CFLAGS += -Wall -fPIC

ifneq (,$(DEBUG))
override CFLAGS+=-O0 -g
else
override CFLAGS+=-O2
endif

ifeq (,$(USE_SYSCALL))
override CFLAGS+=-DUSE_LIBDL
override LDFLAGS+=-ldl
else
override CFLAGS+=-DUSE_SYSCALL
endif

ifneq (,$(STRIP))
override LDFLAGS+=-s
endif

default: $(LIB_OBJS) librandsaddr.a randsaddr.so
all: $(LIB_OBJS) librandsaddr.a randsaddr.so rndaddr

%.o: %.c $(HDRS)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -I. -c -o $@ $<

%.lo: %.c $(HDRS)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -DSHARED -I. -c -o $@ $<

librandsaddr.a: $(LIB_OBJS)
	$(CROSS_COMPILE)$(AR) cru $@ $^
	$(CROSS_COMPILE)ranlib $@

randsaddr.so: $(LDSO_OBJS) librandsaddr.a
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -DSHARED $^ -shared -o $@ librandsaddr.a $(LDFLAGS) -lpthread

rndaddr: $(PROG_OBJS) librandsaddr.a
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $< -o $@ librandsaddr.a $(LDFLAGS)

clean:
	rm -f librandsaddr.a randsaddr.so rndaddr *.o *.lo
