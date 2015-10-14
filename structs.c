#define _POSIX_C_SOURCE 200809L

#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

#include "khash.h"

#include "structs.h"


typedef struct buffer{
    int size;
    void **data;
    int in, out, cnt;
    pthread_mutex_t mutex;
    pthread_cond_t noempty, nofull;;
} Buffer;

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
       pthread_cond_init(&buf->nofull, NULL)) {
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
    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

void free_buffer(Buffer_t *buf)
{
    if(buf->cnt) {
        fprintf(stderr, "Trying to free a non empty Buffer_t %d\n", buf->cnt);
		return;
    }
    free(buf->data);
    free(buf);
}


KHASH_MAP_INIT_STR(h_table, Buffer_t *)

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

int ht_add_element(Hash_t *table, const char *k, Buffer_t *v)
{
    khint_t hint;
    int absent;
    hint = kh_put(h_table, table->h_t, k, &absent);
    if(!absent) {
        kh_del(h_table, table->h_t, hint);
        return 0;
    }
    kh_key(table->h_t, hint) = strdup(k);
    kh_value(table->h_t, hint) = v;
    return 1;
}

static Buffer_t *ht_get_el(Hash_t *table, const char *k, int del)
{
    int is_missing;
    khint_t hint;
    Buffer_t *ret;
    pthread_mutex_lock(&table->get_mutex);
    hint = kh_get(h_table, table->h_t, k);
    is_missing  = (hint == kh_end(table->h_t));
    if(is_missing) {
        kh_del(h_table, table->h_t, hint);
        pthread_mutex_unlock(&table->get_mutex);
        return NULL;
    }
    ret = kh_value(table->h_t, hint);
    if(del) {
        free((char *)kh_key(table->h_t, hint));
        kh_del(h_table, table->h_t, hint);
    }
    pthread_mutex_unlock(&table->get_mutex);
    return ret;
}

Buffer_t *ht_get_element(Hash_t *table, const char *k)
{
    return ht_get_el(table, k, 0);
}

Buffer_t *ht_get_and_delete_element(Hash_t *table, const char *k)
{
    return ht_get_el(table, k, 1);
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
