.PHONY: all clean


ALL_MODULES=$(filter-out logging.c, $(patsubst %.c,%.so,$(wildcard *.c)))

all: $(ALL_MODULES)

COMMON_DEPS=logging.c
desockmulti.so: CFLAGS+=-lpthread -lrt

%.so: %.c $(COMMON_DEPS)
	$(CC) $^ -o $@ -shared -fPIC $(CFLAGS)

clean:
	rm -f *.o
	rm -f *.so