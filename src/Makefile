all: journal2lumberjack

clean:
	rm -f journal2lumberjack.o journal2lumberjack

journal2lumberjack.o: journal2lumberjack.c
	gcc -c $< -std=gnu11 -Wall -Wextra -Werror $(CFLAGS) $(shell pkg-config --cflags zlib libsystemd-journal nspr nss nss-util)

journal2lumberjack: journal2lumberjack.o
	gcc -o $@ $< -std=gnu11 -Wall -Wextra -Werror $(LDFLAGS) $(shell pkg-config --libs zlib libsystemd-journal nspr nss nss-util) -linotifytools
