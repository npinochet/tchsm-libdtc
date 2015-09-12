#ifndef DT_TCLIB_ERR_H_
#define DT_TCLIB_ERR_H_

enum {
    DTC_ERR_NONE,   // Not an error.
    DTC_ERR_NOMEM,  // Not enough memory.
    DTC_ERR_CONFIG_FILE,
    DTC_ERR_ZMQ_ERROR,
    DTC_ERR_ZMQ_CURVE,
    DTC_ERR_CONNECTION,
    DTC_ERR_COMMUNICATION,
    DTC_ERR_SERIALIZATION,
    DTC_ERR_DATABASE,
    DTC_ERR_INTERN,

    DTC_ERR_MAX_ // Keep at the end!!
};

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

    "Wrong errno.",  // Keep at the end.
};

const char *dtc_get_error_msg(int errno) {

    if(errno >= DTC_ERR_MAX_ || errno < 0)
        return err_msgs[DTC_ERR_MAX_];

    return err_msgs[errno];
}

#endif
