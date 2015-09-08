all: journal2lumberjack

clean:
	rm -f journal2lumberjack.o journal2lumberjack

journal2lumberjack.o: journal2lumberjack.c
	gcc -c $< -std=gnu11 -Wall -Wextra -Werror -shared -fPIC $(CFLAGS) $(shell pkg-config --cflags zlib libsystemd-journal)

journal2lumberjack: journal2lumberjack.o
	gcc -o $@ $< -std=gnu11 -Wall -Wextra -Werror -shared $(LDFLAGS) $(shell pkg-config --libs zlib libsystemd-journal) -linotifytools
