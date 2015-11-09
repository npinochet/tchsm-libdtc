#include <check.h>

#include "structs.h"

START_TEST(buffer_simple_timeout)
{
    Buffer_t *buf = newBuffer(10);
    ck_assert_int_eq(0,
                     wait_n_elements(buf, 1, 1));
    free_buffer(buf);
}
END_TEST

START_TEST(hash_init_destroy)
{
    Hash_t *h = ht_init_hashtable();
    ht_free(h);
}
END_TEST

START_TEST(hash_add)
{
    Buffer_t *val = (Buffer_t *)0x123;
    const char *key = "my_key";

    Hash_t *h = ht_init_hashtable();

    ck_assert_int_eq(1, ht_add_element(h, key, val));
    ck_assert_int_eq(0, ht_add_element(h, key, val));

    ht_free(h);
}
END_TEST

START_TEST(hash_put_get)
{

    Buffer_t *val = (Buffer_t *)0x123;
    const char *key = "my_key";
    void *aux;

    Hash_t *h = ht_init_hashtable();
    ht_add_element(h, key, val);
    ck_assert_int_eq(1, ht_get_element(h, key, &aux));
    ck_assert_ptr_eq(val, aux);
    aux = NULL;
    ck_assert_int_eq(1, ht_get_element(h, key, &aux));
    ck_assert_ptr_eq(val, aux);
    aux = NULL;

    ck_assert_int_eq(1, ht_get_and_delete_element(h, key, &aux));
    ck_assert_ptr_eq(val, aux);
/*
    ck_assert_int_eq(0, ht_get_element(h, key, &aux));
    ck_assert_int_eq(0, ht_get_and_delete_element(h, key, &aux));
*/
    ht_free(h);
}
END_TEST

START_TEST(hash_lock_unlock_get)
{
    Buffer_t *val = (Buffer_t *)0x123;
    const char *key = "my_key";
    void *aux;

    Hash_t *h = ht_init_hashtable();
    ht_add_element(h, key, val);
    ht_lock_get(h);
    ck_assert_int_eq(1, ht_get_element(h, key, &aux));
    ck_assert_ptr_eq(val, aux);
    aux = NULL;
    ht_unlock_get(h);
    ck_assert_int_eq(1, ht_get_element(h, key, &aux));
    ck_assert_ptr_eq(val, aux);
    aux = NULL;
    ht_free(h);

}
END_TEST

void add_test_cases(Suite *s)
{
    TCase *test_case = tcase_create("structs");
    tcase_add_test(test_case, hash_init_destroy);
    tcase_add_test(test_case, hash_add);
    tcase_add_test(test_case, hash_put_get);
    tcase_add_test(test_case, hash_lock_unlock_get);

    tcase_add_test(test_case, buffer_simple_timeout);
    suite_add_tcase(s, test_case);
}

int main()
{
    int number_failed = 0;

    Suite *s = suite_create("Struct testing");
    SRunner *runner = srunner_create(s);

    add_test_cases(s);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? 0 : 1;
}

