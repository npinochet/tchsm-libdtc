#ifndef DT_TCLIB_UTILITIES_H_
#define DT_TCLIB_UTILITIES_H_

#include <libconfig.h>

/**
 * Auxiliary function to read an uint16_t from a config_setting_t, it's read
 * as int64 and then tested if it fit in an uint16_t.
 *
 * @param setting setting to perform the lookup.
 * @param name name of the uint16 in the configuration.
 * @param out on success will point to the value looked for.
 *          On error will not be modified.
 *
 * @return DTC_ERR_NONE on success, a proper error code otherwise.
 **/
int lookup_uint16_conf_element(const config_setting_t *setting,
                               const char *name, uint16_t *out);

/**
 * Auxiliary function to read an string from a config_setting_t and copy it
 * into a new memory chunk to persist after the config_setting_t deletion.
 *
 * @param setting setting to perform the lookup.
 * @param name name of the string in the configuration.
 * @param value the copied string will be stored at *value.
 *          On error will not be modified.
 *
 * @return DTC_ERR_NONE on success, a proper error code otherwise.
 *
 **/
int lookup_string_conf_element(const config_setting_t *setting,
                               const char *name, char **value);

#endif // DT_TCLIB_UTILTIES_H_
