#ifndef UNIT_TEST
#error "To run unit test you must define UNIT_TEST"
#endif

#include <check.h>
#include <stdlib.h>

#include "messages.h"

static void add_test_cases(Suite *s){
    suite_add_tcase(s, get_dt_tclib_messages_c_test_case());
}

int main() {
    int number_failed = 0;

    Suite *s = suite_create("Unit_Testing");
    SRunner *runner = srunner_create(s);

    add_test_cases(s);

    srunner_run_all(runner, CK_VERBOSE);
    number_failed = srunner_ntests_failed(runner);
    srunner_free(runner);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
