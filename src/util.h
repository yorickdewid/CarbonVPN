#ifndef UTIL_H
#define UTIL_H

void print_hex(unsigned char *s, size_t n);
void hextobin(unsigned char *v, unsigned char *s, size_t n);
char *c_strdup(const char *str);
int isnull(unsigned char *s, size_t n);

#endif // UTIL_H
