SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
LIB_OBJS = $(filter-out randsaddr_ldso.o, $(SRCS:.c=.o))
LDSO_OBJS = randsaddr_ldso.o
override CFLAGS += -Wall -fPIC

ifneq (,$(DEBUG))
override CFLAGS+=-O0 -g
else
override CFLAGS+=-O2
endif

default: $(LIB_OBJS) librandsaddr.a randsaddr.so
all: $(LIB_OBJS) librandsaddr.a randsaddr.so

%.o: %.c $(HDRS)
	$(CROSS_COMPILE)$(CC) $(CFLAGS) -I. -c -o $@ $<

librandsaddr.a: $(LIB_OBJS)
	$(CROSS_COMPILE)$(AR) cru $@ $^

randsaddr.so: $(LDSO_OBJS) librandsaddr.a
	$(CROSS_COMPILE)$(CC) $(CFLAGS) $< -shared -o $@ librandsaddr.a

clean:
	rm -f librandsaddr.a randsaddr.so *.o
