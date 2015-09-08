#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"

void print_hex(unsigned char *s, size_t n) {
	int i;
	for (i=0; i<n; ++i)
		printf("%02x", (unsigned int)s[i]);
	printf("\n");
}

char *strdup(const char *str) {
	int n = strlen(str) + 1;
	char *dup = malloc(n);
	if(dup)
		strcpy(dup, str);
	return dup;
}
