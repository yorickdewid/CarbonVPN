#ifndef CONF_H
#define CONF_H

#include <stdio.h>

/* Typedef for prototype of handler function. */
typedef int(*conf_handler)(void *_pcfg, const char *section, const char *name, const char *value);

/* Typedef for prototype of fgets-style reader function. */
typedef char *(*conf_reader)(char *str, int num, void *stream);

int conf_parse(const char *filename, conf_handler handler, void *_pcfg);
int conf_parse_file(FILE *file, conf_handler handler, void *_pcfg);
int conf_parse_stream(conf_reader reader, void *stream, conf_handler handler, void *_pcfg);

/* Maximum line length for any line in config file. */
#ifndef CONF_MAX_LINE
#define CONF_MAX_LINE 200
#endif

#endif // CONF_H
