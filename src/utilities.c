#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <string.h>
#include <uuid/uuid.h>

#include <zmq.h>

#include "dtc.h"
#include "utilities.h"

int lookup_uint16_conf_element(const config_setting_t *setting,
                                      const char *name, uint16_t *out)
{
    int ret;
    long long aux;

    ret = config_setting_lookup_int64(setting, name, &aux);
    if(ret != CONFIG_TRUE) {
        LOG_DEBUG(LOG_LVL_CRIT, "%s not found in the configuration.", name);
        return DTC_ERR_CONFIG_FILE;
    }
    if(aux > UINT16_MAX){
        LOG_DEBUG(LOG_LVL_CRIT,
                  "Error getting %s. %d is too big, should fit in uint16_t.",
                  name, aux);
        return DTC_ERR_CONFIG_FILE;
    }

    *out = (uint16_t) aux;
    return DTC_ERR_NONE;
}

int lookup_string_conf_element(const config_setting_t *setting,
                               const char *name, char **value)
{

    int ret;
    const char *char_aux;
    ret = config_setting_lookup_string(setting, name, &char_aux);
    if(ret == CONFIG_FALSE) {
        LOG_DEBUG(LOG_LVL_CRIT, "Error getting %s.", name);
        return DTC_ERR_CONFIG_FILE;
    }
    *value = strdup(char_aux);
    if(*value == NULL) {
        LOG_DEBUG(LOG_LVL_CRIT, "Not enough memory to copy %s.", name);
        return DTC_ERR_NOMEM;
    }
    return DTC_ERR_NONE;
}

/**
 * Generate and dump into ret a uuid, ret must point to at least 37 bytes.
 */
char *get_uuid_as_char(char *ret)
{
    uuid_t uuid;
    uuid_generate(uuid);
    uuid_unparse(uuid, ret);

    return ret;
}

void free_wrapper(void *data, void *hint)
{
    void (*free_function)(void *) = (void (*)(void *))hint;
    free_function(data);
}

static int s_send_str(void *socket, const char *string, int flags)
{
    return zmq_send(socket, string, strlen(string), flags);
}

int s_send(void *socket, const char *string)
{
    return s_send_str(socket, string, 0);
}

int s_sendmore(void *socket, const char *string)
{
    return s_send_str(socket, string, ZMQ_SNDMORE);
}

char *s_recv(void *socket)
{
    char buffer [256];
    int size = zmq_recv(socket, buffer, 255, 0);
    if (size == -1)
        return NULL;
    if (size > 255)
        size = 255;
    buffer[size] = 0;
    return strdup(buffer);
}
