#ifndef DT_TCLIB_DTC_H_
#define DT_TCLIB_DTC_H_

#include "err.h"

struct dtc_ctx;
typedef struct dtc_ctx dtc_ctx_t;

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
 * @return -1 if key_id is already used.
 */
int dtc_generate_key_shares(dtc_ctx_t *ctx, const char *key_id, size_t bit_size,
                            uint16_t threshold, uint16_t cant_nodes,
                            public_key_t **info);

// TODO Implement and document the API.
uint8_t *dtc_sign(dtc_ctx_t *ctx, uint32_t key_id, uint8_t *message,
                  size_t msg_len);

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
