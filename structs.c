#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
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

ConcurrentHash_t *cht_init_hashtable()
{
    return NULL;
}

ConcurrentHash_t *cht_add_element(ConcurrentHash_t *table, char *k, void *v)
{
    return NULL;
}

int cht_get_element(ConcurrentHash_t *table, char *k, void *v)
{
    return 0;
}

void cht_free(ConcurrentHash_t *table)
{
    return;
}
