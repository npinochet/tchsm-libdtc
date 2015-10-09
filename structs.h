#ifndef DT_TCLIB_STRUCTS_H_
#define DT_TCLIB_STRUCTS_H_

struct buffer;
typedef struct buffer Buffer_t;

struct hash_table;
typedef struct hash_table ConcurrentHash_t;
//TODO Fix documentation.
/**
 * Create a new concurrent buffer, size specify its capacity, not enough
 * memory or problems initializing the exclusion structures make this function
 * to return NULL, otherwise the new Buffer_t is returned.
 */
Buffer_t *newBuffer(int size);

/** Add a new value to the buffer, if there is no room space in the buffer, the
 *  function will wait until it can store the new value.
 */
void put(Buffer_t *buf, void *value);

/** As put, but if the buffer is full, it will return 1 and not store the value
 * if the value was stored, it returns 0
 */
int put_nowait(Buffer_t *buf, void *value);

/** Put value at the begining of the buffer, so it will be the first value to
 *  be returned in a get call, if the buffer is full, will wait until it can
 *  store the value.
 */
void put_first(Buffer_t *buf, void *value);

/** Get the next value in the buffer. If the buffer is empty, will wait until
 *  there are any value to return.
 */
void *get(Buffer_t *buf);

/** Get the next value in the buffer, if the buffer is empty will return 1
 *  and will not modify *out, otherwise it will return 0 and set *out as the
 *  value got.
 */
int get_nowait(Buffer_t *buf, void **out);

/** Try to free the buffer, if there are still some values in the buffer, will
 *  not free it, instead will print an error in the stderr.
 */
void free_buffer(Buffer_t *buf);


ConcurrentHash_t *cht_init_hashtable();

ConcurrentHash_t *cht_add_element(ConcurrentHash_t *table, char *k, void *v);

int cht_get_element(ConcurrentHash_t *table, char *k, void *v);

void cht_free(ConcurrentHash_t *table);

#endif
