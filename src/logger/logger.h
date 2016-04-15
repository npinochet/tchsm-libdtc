/*
 * Copyright (c) 2015 NIC Chile Research Labs, Francisco Montoto.
 *
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#undef GET_MACRO
#undef OPEN_LOG
#undef OPEN_LOG0
#undef OPEN_LOG1
#undef OPEN_LOG2
#undef LOG
#undef PERROR_LOG
#undef CLOSE_LOG
#undef PERROR_RET
#undef LOG_EXIT
#undef EXIT_ON_FALSE
#undef PERROR_AND_EXIT_ON_FALSE

#include <syslog.h>

#ifndef LOG_LEVELS
#define LOG_LEVELS

#define LOG_LVL_EMRG LOG_EMERG
#define LOG_LVL_ALRT LOG_ALERT
#define LOG_LVL_CRIT LOG_CRIT
#define LOG_LVL_ERRO LOG_ERR
#define LOG_LVL_WARN LOG_WARNING
#define LOG_LVL_NOTI LOG_NOTICE
#define LOG_LVL_INFO LOG_INFO
#define LOG_LVL_DEBG LOG_DEBUG
#define LOG_LVL_MAX  // Keep at the end!!
#endif


#ifdef NO_LOGGING_

#define OPEN_LOG(...) ((void)0)
#define LOG(...) ((void)0)
#define PERROR_LOG(...) ((void)0)
#define CLOSE_LOG(...) ((void)0)

#else  // NO_LOGGING_

#include <stdio.h>

/**
 * Log a message.
 *
 * Args:
 *  level: Log level of this message.
 *  format: Message to log, printf-like input.
 **/
#define LOG(level, format,...) \
    do { \
        syslog(level, format, ## __VA_ARGS__); \
    } while(0);

#define PERROR_LOG(level, msg, format,...) \
    do { \
        LOG(level, "%s:%s", msg, strerror(errno)) \
        LOG(level, format, ## __VA_ARGS__); \
    } while(0);

#define GET_MACRO(_0, _1, _2, NAME, ...) NAME
#define OPEN_LOG0() openlog(NULL, LOG_CONS, LOG_LOCAL0)
#define OPEN_LOG1 #error "OPEN_LOG receive 0 or 2 arguments, not 1"
#define OPEN_LOG2(ident, option, facility) openlog(ident, option, facility)

#define OPEN_LOG(...) \
            GET_MACRO(_0, ##__VA_ARGS__, \
                      OPEN_LOG2, OPEN_LOG1, OPEN_LOG0)(__VA_ARGS__)
#endif  //NO_LOGGING_
//  The following MACROS will do all the non logging action even if NO_LOGGING_
//  set.

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
