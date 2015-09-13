#define _POSIX_C_SOURCE 200809L

#include <inttypes.h>
#include <string.h>

#include "err.h"
#include "utilities.h"

#ifndef NDEBUG
    #include "logger/logger.h"
    #define LOG_DEBUG(level, format, ...) \
        LOG(level, format, ## __VA_ARGS__)
#else
    #define LOG_DEBUG(level, format, ...) \
        do {}while(0);
#endif

int lookup_uint16_conf_element(const config_setting_t *setting,
                                      const char *name, uint16_t *out) {
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
                               const char *name, char **value) {

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
