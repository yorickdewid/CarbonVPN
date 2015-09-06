all:
	$(CC) -Wall -Werror -pedantic -std=c99 main.c -o tunnel

clean:
	rm -rf tunnel
