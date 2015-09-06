#ifndef LOGGER_H
#define LOGGER_H

void start_log();
void lprintf(const char *format, ...);
void lprint(const char *str);
void stop_log();

#endif // LOGGER_H
