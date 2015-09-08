BINNAME=carbond
all:
	$(CC) -Wall -Werror -pedantic -std=c99 util.c conf.c logger.c main.c -I../libsodium/src/libsodium/include -L. -lsodium -o $(BINNAME)

clean:
	rm -rf $(BINNAME)
