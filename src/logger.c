#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include "logger.h"

static FILE *fp = NULL;
static char log_tty_std = 1;

int start_log(char *logfile) {
	if (!fp) {
		fp = fopen(logfile, "a");
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

void log_tty(char b) {
	log_tty_std = b;
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

	if (log_tty_std) {
		va_start(arglist, format);
		vfprintf(stderr, format, arglist);
		va_end(arglist);
	}
}

void lprint(const char *str) {
	char buf[32];

	if (fp) {
		strftime(buf, 32, "%d/%b/%Y %H:%M:%S %z", get_time());
		fprintf(fp, "[%s] ", buf);
		fputs(str, fp);
	}

	if (log_tty_std)
		fputs(str, stderr);
}

void stop_log() {
	if (fp)
		fclose(fp);
}
