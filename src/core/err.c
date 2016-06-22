#include "include/dtc.h"

const char *err_msgs[] = {
    "Not an error.",
    "Not enough memory.",
    "Error reading config file.",
    "Error at zmq library.",
    "Error setting zmq curve security.",
    "Error in the socket connection.",
    "Communication error.",
    "Error in the serialization.",
    "Sqlite error.",
    "Intern library error.",
    "Invalid parameter.",
    "Timed out",

    "Wrong errno.",  // Keep at the end.
};

const char *dtc_get_error_msg(int err) {

    if(err >= DTC_ERR_MAX_ || err < 0)
        return err_msgs[DTC_ERR_MAX_];

    return err_msgs[err];
}
