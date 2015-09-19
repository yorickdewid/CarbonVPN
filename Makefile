BINNAME=carbond
all:
	$(CC) -g -O0 -Wall -Werror -pedantic -std=c99 vector.c util.c conf.c logger.c main.c -I../libsodium/src/libsodium/include -L. -lsodium -lev -o $(BINNAME)

clean:
	rm -rf $(BINNAME)
