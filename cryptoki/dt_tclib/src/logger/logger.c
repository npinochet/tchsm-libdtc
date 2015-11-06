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

void hexDump (char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x ", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}

