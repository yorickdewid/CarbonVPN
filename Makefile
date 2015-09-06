all:
	$(CC) -Wall -Werror -pedantic -std=c99 util.c main.c -I../libsodium/src/libsodium/include -L. -lsodium -o tunnel

clean:
	rm -rf tunnel
