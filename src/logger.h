#ifndef LOGGER_H
#define LOGGER_H

int start_log();
void log_tty(char b);
void lprintf(const char *format, ...);
void lprint(const char *str);
void stop_log();

#endif // LOGGER_H
