#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "logger.h"

#define LOGFILE		"carbonvpn.log"

static FILE *fp = NULL;

int start_log() {
	if (!fp) {
		fp = fopen(LOGFILE, "a");
		if (fp)
			setvbuf(fp, NULL, _IOLBF, 1024);
		else {
			fputs("[erro] Cannot open log\n", stderr);
			return -1;
		}
	}
	return 0;
}

static struct tm *get_time() {
	time_t rtime;
	struct tm *ltime;

	time(&rtime);
	ltime = localtime(&rtime);

	return ltime;
}

void lprintf(const char *format, ...) {
	va_list arglist;
	char buf[32];

	if (fp) {
		strftime(buf, 32, "%d/%b/%Y %H:%M:%S %z", get_time());
		fprintf(fp, "[%s] ", buf);
		va_start(arglist, format);
		vfprintf(fp, format, arglist);
		va_end(arglist);
	}

	va_start(arglist, format);
	vfprintf(stderr, format, arglist);
	va_end(arglist);
}

void lprint(const char *str) {
	char buf[32];

	if (fp) {
		strftime(buf, 32, "%d/%b/%Y %H:%M:%S %z", get_time());
		fprintf(fp, "[%s] ", buf);
		fputs(str, fp);
	}

	fputs(str, stderr);
}

void stop_log() {
	if (fp)
		fclose(fp);
}
