#ifndef DT_TCLIB_DTC_H_
#define DT_TCLIB_DTC_H_

#include <tc.h>
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
int dtc_generate_key_shares(dtc_ctx_t *ctx, const char *key_id, size_t bit_size,
                            uint16_t threshold, uint16_t cant_nodes,
                            key_metainfo_t **info);

/**
 * Ask the nodes to sign the message using the key_id specified.
 *
 * @param ctx Active dtc context.
 * @param key_metainfo Metainfo of the key referenced by key_id, this struct is
 *      obtained after a successful call to dtc_generate_key_shares and
 *      contains info about the key.
 * @param key_id Id of the key to be used to generate the signature.
 * @param message Message to be signed, the message must be already prepared,
 *      see tc_prepare_document.
 * @param out The signature will be stored at *out. On success the user is
 *      responsible for the memory and should call tc_clear_bytes it order to
 *      avoid a memory leak. On error out is not changed.
 *
 * @return DTC_ERR_NONE on success, a proper error code otherwise.
 */
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
