#ifndef DT_TCLIB_STRUCTS_H_
#define DT_TCLIB_STRUCTS_H_

struct buffer;
typedef struct buffer Buffer_t;

struct hash_table;
typedef struct hash_table Hash_t;
//TODO Fix Buffer documentation.
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

/**
 *  Alloc and create a hashtable to store (const char *, Buffer_t) pairs.
 */
Hash_t *ht_init_hashtable();

/**
 *  Add an element to the hashtable.
 *
 *  @param table Table to add into.
 *  @param k Key, will be copied to be stored, so it's safe to delete it after
 *      this function returns.
 *  @param v Value of the element. Do not store NULL pointers, the behaviour is
 *      undefined.
 *
 *  @return 1 if the element could be added, 0 if it wasn't. An element won't be
 *      inserted if the key was already in the table.
 */
int ht_add_element(Hash_t *table, const char *k, Buffer_t *v);

/**
 * Lock the get function in the table, since this function returns no other
 * thread can get an element from the table.
 *
 * @param table table to lock.
 */
void ht_lock_get(Hash_t *table);

/**
 * Unlock the get funcion, should be called once by each time ht_lock_get is
 * called.
 *
 * @param table table to unlock.
 */
void ht_unlock_get(Hash_t *table);

/**
 * Get a value from the table.
 *
 * @param table Table where to look for the element.
 * @param k Key of the value to be returned.
 *
 * @return The value if the key was present in table, NULL otherwise.
 */
Buffer_t *ht_get_element(Hash_t *table, const char *k);

/**
 * Get a value from the table and remove it.
 *
 * @param table Table where to look for the element.
 * @param k Key of the value to be returned.
 *
 * @return The value if the key was present in table, NULL otherwise.
 */
Buffer_t *ht_get_and_delete_element(Hash_t *table, const char *k);

/**
 *  Delete and deallocate the hashtable, if elements are present, will free the
 *  keys and delete the values, the pointed memory of the value will not be free
 *  by this function. To call this function no other thread should be using the
 *  table and the get funcion can not be lock by ht_get_lock.
 */
void ht_free(Hash_t *table);

#endif
