#ifndef DT_TCLIB_DTC_H_
#define DT_TCLIB_DTC_H_

#include "err.h"

struct dtc_ctx;
typedef struct dtc_ctx dtc_ctx_t;

/**
 * Allocate and create a new context, the returned context is ready to perform
 * operations.
 *
 * @param config_file Path to the config file for the context.
 * @param err If it's specified will be set with a proper error by the time the
 *      function returns. Otherwise you can pass NULL.
 *
 * @return An active context on success or NULL on error.
 */
dtc_ctx_t *dtc_init(const char *config_file, int *err);

/**
 * Generate and distribute among the nodes the nodes a new key.
 *
 * @param ctx Active dtc context, the key will be owned by it. But will
 *      not be destroyed if the context is.
 * @param key_id Identificator of the key, is a user defined char *, and
 *      it's unique within a context.
 * @param bit_size //TODO
 * @param threshold //TODO
 * @param cant_nodes //TODO
 * @param info //TODO
 *
 * @return -1 if key_id is already used. //TODO
 */
// TODO Do we move the key_id to uint{32-64}_t ?
int dtc_generate_key_shares(dtc_ctx_t *ctx, const char *key_id, size_t bit_size,
                            uint16_t threshold, uint16_t cant_nodes,
                            key_metainfo_t **info);
//TODO Would be nice to provide a tc_clear_bytes in this header.
// TODO Implement and document the API.
int dtc_sign(dtc_ctx_t *ctx, const key_metainfo_t *key_metainfo,
                  const char *key_id, bytes_t *message, bytes_t **out);

/**
 * This is a best effort deletion of the key in the nodes, the library will not
 * wait the nodes to reply or even to know if them received the message.
 *
 * @param ctx Active dtc context.
 * @param key_id Identificator of the key.
 */
void dtc_delete_key_shares(dtc_ctx_t *ctx, const char *key_id);

/**
 * Destroy the context and free all the memory allocated by it. The destruction
 * will not delete the generated keys, since them live in the nodes.
 *
 * @param ctx The context to be destroyed.
 */
int dtc_destroy(dtc_ctx_t *ctx);

const char *dtc_get_error_msg(int errno);

#endif
