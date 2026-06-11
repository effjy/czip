CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDLIBS  := -lsodium -lzstd
PREFIX  ?= /usr/local

czip: czip.c
	$(CC) $(CFLAGS) -o $@ czip.c $(LDLIBS)

install: czip
	install -Dm755 czip $(DESTDIR)$(PREFIX)/bin/czip

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/czip

clean:
	rm -f czip

.PHONY: install uninstall clean
