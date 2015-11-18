#ifndef DT_TCLIB_STRUCTS_H_
#define DT_TCLIB_STRUCTS_H_

#include <inttypes.h>
#include <sys/time.h>

struct buffer;
typedef struct buffer Buffer_t;

struct hash_table;
typedef struct hash_table Hash_t;

struct uint16_hash_table;
typedef struct uint16_hash_table Uint16_Hash_t;

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

/**
 * Wait until the buffer has no elements. It also can bound the duration of the
 * wait and return after the specified timeout.
 *
 * This will wait until the buffer has no elements to return, however
 * there is no guaranteed that every time that the buffer gets empty it will
 * return, another thread might put a new value before this thread wake up.
 * There is also not guaranteed that after this function returns the buffer
 * will be still empty. If there are no threads adding elements this function
 * will return any time the buffer gets empty.
 * The timeout is defined by timeout_sec + timeout_usec.
 *
 * @param buf The buffer.
 * @param timeout_sec segs of timeout, if it is 0 and timeout_usec is 0, it will
 *      wait forever.
 * @param timeout_usec microsecs of timeout, if it is 0 and timeout_sec is 0,
 *      it will wait forever.
 *
 * @return 1 if returned because an empty buffer, 0 if it returned on timeout.
 */
int wait_until_empty(Buffer_t *buf, unsigned timeout_sec,
                     unsigned timeout_usec);

/**
 * Wait until there are at least n element in the buffer.
 * This will return iff there are at least n elements in the buffer, but it's
 * not guaranteed that every time that there are n or more elements it will
 * return, since the n element might be returned by a get before this function
 * cah check it. That said, if there are no get waiting for elements, it will
 * return each time the list has at least n elements. Be aware that if you're
 * getting elements from the bufer once this function returns the list might
 * have less than n elements.
 *
 * @param buf The buffer.
 * @param n The amount of elements to wait for.
 *
 * @return 1 if returned because the buffer has at least n elements, 0 if it
 *      returned on timeout.
 */
int wait_n_elements(Buffer_t *buf, unsigned n, unsigned timeout);

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
 *  @param v Value of the element.
 *
 *  @return 1 if the element could be added, 0 if it wasn't. An element won't be
 *      inserted if the key was already in the table.
 */
int ht_add_element(Hash_t *table, const char *k, void *v);

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
 * @param out If it isn't NULL and k exists, will point to the value of the
 *      element stored with k.
 *
 * @return 1 if the element is present, 0 if it's not.
 */
int ht_get_element(Hash_t *table, const char *k, void **out);

/**
 * Get a value from the table and remove it.
 *
 * @param table Table where to look for the element.
 * @param k Key of the value to be returned.
 * @param out If it isn't NULL and k exists, will point to the value of the
 *      element stored with k.
 *
 * @return 1 if the element is present, 0 if it's not.
 */
int ht_get_and_delete_element(Hash_t *table, const char *k, void **out);

/**
 *  Delete and deallocate the hashtable, if elements are present, will free the
 *  keys and delete the values, the pointed memory of the value will not be free
 *  by this function. To call this function no other thread should be using the
 *  table and the get funcion can not be lock by ht_get_lock.
 */
void ht_free(Hash_t *table);

/**
 *  Alloc and create a hashtable to store (const char *, uint16_t) pairs.
 */
Uint16_Hash_t *uht_init_hashtable();

/**
 *  Add an element to the hashtable.
 *
 *  @param table Table to add into.
 *  @param k Key, will be copied to be stored, so it's safe to delete it after
 *      this function returns.
 *  @param v Value of the element.
 *
 *  @return 1 if the element could be added, 0 if it wasn't. An element won't be
 *      inserted if the key was already in the table.
 */
int uht_add_element(Uint16_Hash_t *table, const char *k, uint16_t v);

/**
 * Get a value from the table.
 *
 * @param table Table where to look for the element.
 * @param k Key of the value to be returned.
 * @param out If it isn't NULL and k exists, will point to the value of the
 *      element stored with k.
 *
 * @return 1 if the element is present, 0 if it's not.
 */
int uht_get_element(Uint16_Hash_t *table, const char *k, uint16_t *out);

/**
 * Get a value from the table and remove it.
 *
 * @param table Table where to look for the element.
 * @param k Key of the value to be returned.
 * @param out If it isn't NULL and k exists, will point to the value of the
 *      element stored with k.
 *
 * @return 1 if the element is present, 0 if it's not.
 */
int uht_get_and_delete_element(Uint16_Hash_t *table, const char *k,
                               uint16_t *out);

/**
 * Iterate over the elements of the table.
 *
 * @param table Table to iterate over.
 * @param prev_it Last elemet got, to start an iteration should point to zero,
 *      the function will update this value, you don't need to change within a
 *      iteration.
 * @param key If not NULL, will point to the key of the element, you must not
 *      modify *key or **key, this would lead to undefined results.
 * @param val If not NULL will point to the value of the element.
 *
 * @return Will return 1 if the function found an element, 0 if it did not. The
 *      key and val parameter will be set only if this function returned 1,
 *      once the function return 0 there are no more elements in the table to
 *      iterate over.
 */
int uht_next(Uint16_Hash_t *table, unsigned *prev_it, const char **key,
                uint16_t *val);

/**
 *  Delete and deallocate the hashtable, if elements are present, will free the
 *  keys and delete the values, the pointed memory of the value will not be free
 *  by this function. To call this function no other thread should be using the
 *  table.
 */
void uht_free(Uint16_Hash_t *table);

#endif
