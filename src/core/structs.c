#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "khash.h"

#include "include/structs.h"


typedef struct buffer{
    int size;
    void **data;
    int in, out, cnt;
    pthread_mutex_t mutex;
    pthread_cond_t noempty, nofull, wait_n_elements;
} Buffer;

static void get_wait_timespec(time_t secs, suseconds_t microsec,
                              struct timespec *out)
{
    struct timeval now;
    long nanosecs;
    gettimeofday(&now, NULL);
    // now microsecs * 1000 + timeout microsecs * 1000
    nanosecs = now.tv_usec * 1000 + microsec * 1000;

    // 1 000 000 000 nanosecs are one sec.
    // now secs + time out secs + secs in nanosecs
    out->tv_sec = now.tv_sec + secs + nanosecs / (1000 * 1000 * 1000);
    out->tv_nsec = nanosecs % (1000 * 1000 * 1000);
}

/* Creates a new Concurrent buffer */
Buffer_t *newBuffer(int size)
{
    Buffer_t *buf = (Buffer_t *) malloc(sizeof(Buffer_t));
    if(buf == NULL)
        return NULL;
    buf->size = size;
    buf->data = (void **)malloc(sizeof(void *) * size);
    buf->in = buf->out = buf->cnt = 0;
    if(!buf->data)
        goto err_exit;
    if(pthread_mutex_init(&buf->mutex, NULL) ||
       pthread_cond_init(&buf->noempty, NULL) ||
       pthread_cond_init(&buf->nofull, NULL) ||
       pthread_cond_init(&buf->wait_n_elements, NULL)) {
        free(buf->data);
        goto err_exit;
    }
    return buf;

err_exit:
    free(buf);
    return NULL;
}

/* Add an element to the buffer, if the buffer is full put will wait until
 * there are space to put value.*/
void put(Buffer_t *buf, void *value)
{
    pthread_mutex_lock(&buf->mutex);
    while(buf->cnt == buf->size)
        pthread_cond_wait(&buf->nofull, &buf->mutex);
    buf->data[buf->in] = value;
    buf->in = (buf->in + 1) % buf->size;
    buf->cnt++;
    pthread_cond_signal(&buf->noempty);
    pthread_cond_broadcast(&buf->wait_n_elements);
    pthread_mutex_unlock(&buf->mutex);
}

int put_nowait(Buffer_t *buf, void *value)
{
    pthread_mutex_lock(&buf->mutex);
    if(buf->cnt == buf->size) {
		pthread_mutex_unlock(&buf->mutex);
		return 1;
	}
    buf->data[buf->in] = value;
    buf->in = (buf->in + 1) % buf->size;
    buf->cnt++;
    pthread_cond_signal(&buf->noempty);
    pthread_cond_broadcast(&buf->wait_n_elements);
    pthread_mutex_unlock(&buf->mutex);
	return 0;
}

void put_first(Buffer_t *buf, void *value)
{
	pthread_mutex_lock(&buf->mutex);
	while(buf->cnt == buf->size)
		pthread_cond_wait(&buf->nofull, &buf->mutex);
	buf->out = buf->out == 0 ? buf->size - 1 : buf->out - 1;
	buf->data[buf->out] = value;
	buf->cnt++;
	pthread_cond_signal(&buf->noempty);
    pthread_cond_broadcast(&buf->wait_n_elements);
	pthread_mutex_unlock(&buf->mutex);
}

/* Get an element from the buffer, if the buffer is empty, get will wait
 * until there is an element available */
void *get(Buffer_t *buf)
{
    void *value;
    pthread_mutex_lock(&buf->mutex);
    while(buf->cnt == 0)
        pthread_cond_wait(&buf->noempty, &buf->mutex);
    value = buf->data[buf->out];
    buf->out = (buf->out + 1) % buf->size;
    buf->cnt--;
    pthread_cond_signal(&buf->nofull);
    pthread_cond_broadcast(&buf->wait_n_elements);
    pthread_mutex_unlock(&buf->mutex);
    return value;
}

int get_nowait(Buffer_t *buf, void **out)
{
    pthread_mutex_lock(&buf->mutex);
    if(buf->cnt == 0) {
        pthread_mutex_unlock(&buf->mutex);
        return 1;
    }
    *out = buf->data[buf->out];
    buf->out = (buf->out + 1) % buf->size;
    buf->cnt--;
    pthread_cond_signal(&buf->nofull);
    pthread_cond_broadcast(&buf->wait_n_elements);
    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

int wait_until_empty(Buffer_t *buf, unsigned timeout_sec,
                     unsigned timeout_usec)
{
    struct timespec ts;
    get_wait_timespec(timeout_sec, timeout_usec, &ts);
    int ret;
    pthread_mutex_lock(&buf->mutex);
    while(buf->cnt != 0) {
        if(!timeout_sec && !timeout_usec)
            ret = pthread_cond_wait(&buf->wait_n_elements, &buf->mutex);
        else
            ret = pthread_cond_timedwait(&buf->wait_n_elements, &buf->mutex, &ts);
        if(ret == ETIMEDOUT) {
            pthread_mutex_unlock(&buf->mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&buf->mutex);
    return 1;
}

int wait_n_elements(Buffer_t *buf, unsigned n, unsigned timeout_sec,
                    unsigned timeout_usec)
{
    struct timespec ts;
    get_wait_timespec(timeout_sec, timeout_usec, &ts);
    int ret;

    pthread_mutex_lock(&buf->mutex);
    while(buf->cnt < n) {
        if(!timeout_sec && !timeout_usec)
            ret = pthread_cond_wait(&buf->wait_n_elements, &buf->mutex);
        else
            ret = pthread_cond_timedwait(&buf->wait_n_elements, &buf->mutex, &ts);
        if(ret == ETIMEDOUT) {
            pthread_mutex_unlock(&buf->mutex);
            return 0;
        }
    }
    pthread_mutex_unlock(&buf->mutex);
    return 1;
}

void free_buffer(Buffer_t *buf)
{
    if(buf->cnt) {
        fprintf(stderr, "Trying to free a non empty Buffer_t %d\n", buf->cnt);
		return;
    }
    pthread_cond_destroy(&buf->wait_n_elements);
    pthread_cond_destroy(&buf->noempty);
    pthread_cond_destroy(&buf->nofull);
    pthread_mutex_destroy(&buf->mutex);
    free(buf->data);
    free(buf);
}

KHASH_MAP_INIT_STR(u_table, uint16_t)

typedef struct uint16_hash_table {
    khash_t(u_table) *h_t;
    pthread_mutex_t get_mutex;
} Uint16_Hash_t;

Uint16_Hash_t *uht_init_hashtable()
{
    Uint16_Hash_t *ret  = (Uint16_Hash_t *) malloc(sizeof(Uint16_Hash_t));

    ret->h_t = kh_init(u_table);

    pthread_mutexattr_t mta;
    pthread_mutexattr_init(&mta);
    pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);

    pthread_mutex_init(&ret->get_mutex, &mta);

    pthread_mutexattr_destroy(&mta);

    return ret;
}

int uht_add_element(Uint16_Hash_t *table, const char *k, uint16_t v)
{
    khint_t hint;
    int absent;
    pthread_mutex_lock(&table->get_mutex);
    hint = kh_put(u_table, table->h_t, k, &absent);
    if(!absent) {
        kh_del(u_table, table->h_t, hint);
        pthread_mutex_unlock(&table->get_mutex);
        return 0;
    }
    kh_key(table->h_t, hint) = strdup(k);
    kh_value(table->h_t, hint) = v;
    pthread_mutex_unlock(&table->get_mutex);
    return 1;
}

static int uht_get_el(Uint16_Hash_t *table, const char *k, uint16_t *out,
                      int del)
{
    int is_missing;
    khint_t hint;
    pthread_mutex_lock(&table->get_mutex);
    hint = kh_get(u_table, table->h_t, k);
    is_missing  = (hint == kh_end(table->h_t));
    if(is_missing) {
        kh_del(u_table, table->h_t, hint);
        pthread_mutex_unlock(&table->get_mutex);
        return 0;
    }
    if(out)
        *out = kh_value(table->h_t, hint);
    if(del) {
        free((char *)kh_key(table->h_t, hint));
        kh_del(u_table, table->h_t, hint);
    }
    pthread_mutex_unlock(&table->get_mutex);
    return 1;
}

int uht_get_element(Uint16_Hash_t *table, const char *k, uint16_t *out)
{
    return uht_get_el(table, k, out, 0);
}

int uht_get_and_delete_element(Uint16_Hash_t *table, const char *k,
                               uint16_t *out)
{
    return uht_get_el(table, k, out, 1);
}

int uht_next(Uint16_Hash_t *table, unsigned *prev_it, const char **key,
             uint16_t *val)
{
    khash_t(u_table) *t = table->h_t;
    unsigned k = *prev_it;
    khint_t hint;
    const char *key_;

    if(k >= kh_end(t))
        return 0;

    for(;k < kh_end(t); k++)
        if(kh_exist(t, k))
            break;

    *prev_it = k + 1;
    if(k >= kh_end(t))
        return 0;

    key_ = kh_key(t, k);

    if(key)
        *key = key_;
    if(val) {
        hint = kh_get(u_table, t, key_);
        *val = kh_value(t, hint);
    }
    return 1;
}

void uht_free(Uint16_Hash_t *table)
{
    int k;
    khash_t(u_table) *t = table->h_t;
    if(kh_size(t)) {
        for(k = 0; k < kh_end(t); k++) {
            if(kh_exist(t, k)) {
                free((char *)kh_key(t, k));
            }
        }
    }
    pthread_mutex_destroy(&table->get_mutex);
    kh_destroy(u_table, t);
    free(table);
}

KHASH_MAP_INIT_STR(h_table, void *)

typedef struct hash_table{
    khash_t(h_table) *h_t;
    pthread_mutex_t get_mutex;
} Hash_t;

Hash_t *ht_init_hashtable()
{
    Hash_t *ret = (Hash_t *) malloc(sizeof(Hash_t));
    ret->h_t = kh_init(h_table);

    pthread_mutexattr_t mta;
    pthread_mutexattr_init(&mta);
    pthread_mutexattr_settype(&mta, PTHREAD_MUTEX_RECURSIVE);

    pthread_mutex_init(&ret->get_mutex, &mta);

    pthread_mutexattr_destroy(&mta);

    return ret;
}

void ht_lock_get(Hash_t *table)
{
    pthread_mutex_lock(&table->get_mutex);
}

void ht_unlock_get(Hash_t *table)
{
    pthread_mutex_unlock(&table->get_mutex);
}

int ht_add_element(Hash_t *table, const char *k, void *v)
{
    khint_t hint;
    int absent;
    pthread_mutex_lock(&table->get_mutex);
    hint = kh_put(h_table, table->h_t, k, &absent);
    if(!absent) {
        kh_del(h_table, table->h_t, hint);
        pthread_mutex_unlock(&table->get_mutex);
        return 0;
    }
    kh_key(table->h_t, hint) = strdup(k);
    kh_value(table->h_t, hint) = v;
    pthread_mutex_unlock(&table->get_mutex);
    return 1;
}

static int ht_get_el(Hash_t *table, const char *k, void **out, int del)
{
    int is_missing;
    khint_t hint;
    pthread_mutex_lock(&table->get_mutex);
    hint = kh_get(h_table, table->h_t, k);
    is_missing  = (hint == kh_end(table->h_t));
    if(is_missing) {
        kh_del(h_table, table->h_t, hint);
        pthread_mutex_unlock(&table->get_mutex);
        return 0;
    }
    if(out)
        *out = kh_value(table->h_t, hint);
    if(del) {
        free((char *)kh_key(table->h_t, hint));
        kh_del(h_table, table->h_t, hint);
    }
    pthread_mutex_unlock(&table->get_mutex);
    return 1;
}

int ht_get_element(Hash_t *table, const char *k, void **out)
{
    return ht_get_el(table, k, out, 0);
}

int ht_get_and_delete_element(Hash_t *table, const char *k, void **out)
{
    return ht_get_el(table, k, out, 1);
}

void ht_free(Hash_t *table)
{
    int k;
    khash_t(h_table) *t = table->h_t;
    if(kh_size(t)) {
        for(k = 0; k < kh_end(t); k++) {
            if(kh_exist(t, k)) {
                free((char *)kh_key(t, k));
            }
        }
    }
    pthread_mutex_destroy(&table->get_mutex);
    kh_destroy(h_table, t);
    free(table);
}
