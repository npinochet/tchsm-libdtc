#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static FILE *output = NULL;

void logger_init(const char *name) {
    output = fopen(name, "a+");
    if(output == NULL)
        perror("Logger init failed.");
}

void logger_init_stream(FILE *stream) {
    output = stream;
}

void logger_log(int level, const char *file, int line, const char *format, ...)
{
    static const char *levels[] = {"NONE",  "CRIT",
                                   "ERRO",  "WARN",
                                   "NOTI",  "LOG ",
                                   "DEBG",  "MAX "};
    if(!output)
        output = stderr;
    char buff[50];
    size_t writed_bytes = 0;
    va_list args;
    va_start(args, format);
    struct tm *current_tm;
    time_t now = time(NULL);
    current_tm = gmtime(&now);

    writed_bytes = strftime(buff, sizeof(buff),"%Y-%m-%d %H:%M:%S",
                            current_tm);

    // This is not thread safe, use a mutex or one call to write to make it TS.
    fprintf(output, "%s at %s:%d %s: ", buff, file, line, levels[level]);
    vfprintf(output, format, args);
    fprintf(output, "\n");

}

void logger_close() {
    if(output)
        fclose(output);
}
