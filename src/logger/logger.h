#ifndef LOGGER_LOGGER_H
#define LOGGER_LOGGER_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/**
 * Initialize the logger to a file. Will create the file if it does not
 * exists and if does exists will append to it.
 *
 * Args:
 *  name: Name/Path to the file to log in.
 **/
void logger_init(const char *name);

/**
 * Initialize the logger directly to the stream provided.
 *
 * Args:
 *  stream: FILE to log into.
 **/
void logger_init_stream(FILE *stream);

/**
 * Log call, do not use this directly. instead use the MACROs defied below.
 **/
void logger_log(int level, const char *file, int line, const char *format, ...);

/**
 * If the logger was initialized with logger_init, the program should call
 * this function to close the file.
 **/
void logger_close();

/**
 * LOG levels.
 **/
enum {
    LOG_LVL_NONE, // 0
    LOG_LVL_CRIT, // 1
    LOG_LVL_ERRO, // 3
    LOG_LVL_WARN, // 2
    LOG_LVL_NOTI, // 3
    LOG_LVL_LOG,  // 4
    LOG_LVL_DEBG, // 5

    LOG_LVL_MAX   // Keep at the end!!
};

/**
 * Log a message if level is less or equal the current logging level.
 * TODO Implement logging level. Currently logging everything.
 *
 * Args:
 *  level: Log level of this message.
 *  format: Message to log, printf-like input.
 **/
#define LOG(level, format,...) \
    do { \
        logger_log(level, __FILE__, __LINE__, format, ## __VA_ARGS__); \
    } while(0);

#define PERROR_LOG(level, msg, format,...) \
    do { \
        LOG(level, "%s:%s", msg, strerror(errno)) \
        LOG(level, format, ## __VA_ARGS__); \
    } while(0);

/**
 * Log a perror-like message. And returns val.
 *
 * Args:
 *  val: value to be returned.
 *  msg: char* with the message to be logged before the strerror from errno.
 *
 * Returns:
 *  val
 **/
#define PERROR_RET(val, msg) \
    do { \
            LOG(LOG_LVL_ERRO, "%s:%s", msg, strerror(errno)) \
            return val; \
    } while(0);

#define LOG_EXIT(format, ...) \
    do {\
        LOG(LOG_LVL_CRIT, format, ## __VA_ARGS__) \
        exit(1); \
    } while(0);


/**
 * If val evaluates to false, log as critical the format message and
 * call exit(1). Otherwise does nothing.
 *
 * Args:
 *  val: Value to decide if log and exit or not.
 *  formtat: Message to log, printf-like format.
 **/
#define EXIT_ON_FALSE(val, format, ...) \
    do { \
        if (!val) {\
            LOG_EXIT(format, ## __VA_ARGS__) \
        } \
    } while(0);

#define PERROR_AND_EXIT_ON_FALSE(val, msg, format, ...) \
    do{ \
        if (!val) { \
            LOG(LOG_LVL_ERRO, "%s: %s", msg, strerror(errno)) \
            EXIT_ON_FALSE(val, format, ## __VA_ARGS__) \
        } \
    } while(0);

void hexDump (char *desc, void *addr, int len);
#endif
