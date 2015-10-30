#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h> // TODO Just for the sleep, remove it.

#include <libconfig.h>
#include <zmq.h>

#include <tc.h>

#include "dtc.h"
#include "err.h"
#include "messages.h"
#include "structs.h"
#include "utilities.h"

#ifndef NDEBUG
    #include "logger/logger.h"
    #define LOG_DEBUG(level, format, ...) \
        LOG(level, format, ## __VA_ARGS__)
#else
    #define LOG_DEBUG(level, format, ...) \
        do {}while(0);
#endif

#define SEND_ROUTER_INPROC_BINDING "inproc://send_router"
#define CLOSE_SOCKET_ROUTER_THREAD_BINDING "inproc://close_router_thread"

const uint16_t DEFAULT_TIMEOUT = 10;


struct dtc_ctx {

    char *server_id;

    // Timeout for the operations.
    uint16_t timeout;

    // Communication
    void *zmq_ctx;
    void *pub_socket;
    void *router_socket;

    //Router socket thread
    pthread_t router_socket_thr_pid;

    Hash_t *expected_msgs[OP_MAX];
};

struct node_info {
    char *ip;
    uint16_t sub_port;
    uint16_t dealer_port;

    // Communication key.
    char *public_key;
};

struct configuration {
    // Path to the configuration file.
    const char *configuration_file;

    uint16_t timeout;

    uint32_t cant_nodes;
    struct node_info *nodes;

    char *server_id;

    // Curve Security
    char *public_key;
    char *private_key;
};

struct router_socket_handler_data {
    void *zmq_ctx;
    void *router_socket;
    void *inproc_socket;
    void *close_thread_socket;
    Hash_t *expected_msgs[OP_MAX];
};

struct handle_store_key_data {
    Buffer_t *keys;
    Uint16_Hash_t *users_delivered;
    key_metainfo_t *meta_info;
};

struct handle_sign_key_data {
    Buffer_t *signatures;
    const bytes_t *prepared_doc;
    const key_metainfo_t *key_metainfo;
};

static void free_wrapper(void *data, void *hint)
{
    void (*free_function)(void *) = (void (*)(void *))hint;
    free_function(data);
}

static void free_nodes(unsigned int cant_nodes, struct node_info *node)
{
    unsigned int i;
    if(!node)
        return;
    for(i = 0; i < cant_nodes; i++){
        if(node[i].ip)
            free(node[i].ip);
    }
    free(node);
}

static void free_conf(struct configuration *conf)
{
    unsigned i;
    if(!conf)
        return;
    for(i = 0; i < conf->cant_nodes; i++)
        if(conf->nodes[i].public_key)
            free(conf->nodes[i].public_key);
    free_nodes(conf->cant_nodes, conf->nodes);
    conf->cant_nodes = 0;
    if(conf->public_key)
        free(conf->public_key);
    if(conf->private_key) {
        memset(conf->private_key, '\0', strlen(conf->private_key));
        free(conf->private_key);
    }
    if(conf->server_id)
        free(conf->server_id);
}

static int s_send(void *socket, const char *string)
{
    return zmq_send(socket, string, strlen(string), 0);
}

static int s_sendmore(void *socket, const char *string)
{
    int size = zmq_send (socket, string, strlen(string), ZMQ_SNDMORE);
    return size;
}

/* Return a human readable version of the configuration */
static char* configuration_to_string(const struct configuration *conf)
{
    /* Be aware, this memory is shared among the aplication, this function
     * should be called just once or the memory of the previous calls might get
     * corrupted.
     */
    static const int BUFF_SIZE = 500;
    static char buff[BUFF_SIZE];
    int space_left = BUFF_SIZE;
    unsigned int i;

    space_left -= snprintf(buff, space_left,
                           "Configuration File:\t%s\nTimeout:\t\t%" PRIu16 "\n"
                           "Server id:\t\t%s\nNodes:",
                           conf->configuration_file, conf->timeout,
                           conf->server_id);

    for(i = 0; i < conf->cant_nodes; i++) {
        space_left -= snprintf(buff + (BUFF_SIZE - space_left), space_left,
                               "\n\t\t\t%s:{%" PRIu16 ",%" PRIu16 "}",
                               conf->nodes[i].ip, conf->nodes[i].sub_port,
                               conf->nodes[i].dealer_port);
        if(space_left <= 0) {
            LOG(LOG_LVL_ERRO, "Not enough space in the buff to dump the conf");
            break;
        }
    }

    return &buff[0];
}

static char *s_recv (void *socket)
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

static int send_router_msg(void *zmq_ctx, const struct op_req *op,
                           const char *user)
{
    char *serialized_msg;
    int ret;
    size_t msg_size;
    void *sock;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;

    sock = zmq_socket(zmq_ctx, ZMQ_PUSH);
    if(!sock) {
        LOG_DEBUG(LOG_LVL_ERRO, "zmq_socket:%s", zmq_strerror(errno))
        return 0;
    }

    ret = zmq_connect(sock, SEND_ROUTER_INPROC_BINDING);
    if(ret != 0) {
        LOG_DEBUG(LOG_LVL_ERRO, "zmq_connect:%s", zmq_strerror(errno))
        return 0;
    }

    msg_size = serialize_op_req(op, &serialized_msg);
    if(!msg_size) {
        LOG_DEBUG(LOG_LVL_ERRO, "Serialization at send_router_msg")
        return 0;
    }

    ret = zmq_msg_init_data(msg, serialized_msg, msg_size, free_wrapper, free);
    if(ret) {
        LOG_DEBUG(LOG_LVL_ERRO, "Unable to init msg: %s", zmq_strerror(errno))
        free(serialized_msg);
        goto err_exit;
    }

    ret = s_sendmore(sock, user);
    if(ret == 0) {
        LOG_DEBUG(LOG_LVL_ERRO, "Not able to send user")
        zmq_msg_close(msg);
        goto err_exit;
    }

    ret = zmq_msg_send(msg, sock, 0);
    if(ret == 0) {
        zmq_msg_close(msg);
        goto err_exit;
    }

    zmq_close(sock);
    return 1;

err_exit:
    zmq_close(sock);
    return 0;
}

static void free_nodes(unsigned int cant_nodes, struct node_info *node);
static int set_client_socket_security(void *socket,
                                      const char *client_secret_key,
                                      const char *client_public_key);
static int create_connect_sockets(const struct configuration *conf,
                                  struct dtc_ctx *ctx);
static int read_configuration_file(struct configuration *conf);
static int send_pub_op(struct op_req *pub_op, void *socket);
static int start_router_socket_handler(dtc_ctx_t *ctx);
static int close_router_thread(void *zmq_ctx);
static int store_key_shares_nodes(dtc_ctx_t *ctx, const char *key_id,
                                  uint16_t cant_nodes,
                                  key_metainfo_t **key_metainfo,
                                  key_share_t **key_shares);

int main(int argc, char **argv)
{
    int ret_val = 0;
    key_metainfo_t *info = NULL;

    logger_init_stream(stderr);
    LOG(LOG_LVL_NOTI, "Logger started for %s", argv[0]);

    dtc_ctx_t *ctx = dtc_init(NULL, &ret_val);

    printf("Init ret: %d\n", ret_val);
    if(ret_val != DTC_ERR_NONE)
        return 1;

    sleep(1);

    ret_val = dtc_generate_key_shares(ctx, "hola_id", 512, 2, 2, &info);
    printf("Generate: %d\n", ret_val);
    if(ret_val != DTC_ERR_NONE)
        return 1;

    tc_clear_key_metainfo(info);

    dtc_delete_key_shares(ctx, "hola_id");

    printf("Destroy: %d\n", dtc_destroy(ctx));

    return 0;
}

dtc_ctx_t *dtc_init(const char *config_file, int *err)
{
    struct configuration conf;
    int error;
    char *default_conf_file = "./config";

    if(config_file)
        conf.configuration_file = config_file;
    else
        conf.configuration_file = default_conf_file;

    conf.cant_nodes = 0;
    conf.nodes = NULL;
    conf.public_key = NULL;
    conf.private_key = NULL;
    conf.server_id = NULL;

    if(!err)
        err = &error;

    *err = DTC_ERR_NONE;

    dtc_ctx_t *ret = (dtc_ctx_t *) malloc(sizeof(dtc_ctx_t));
    if(!ret) {
        *err = DTC_ERR_NOMEM;
        return NULL;
    }

    *err = read_configuration_file(&conf);
    if(*err != DTC_ERR_NONE)
        goto err_exit;

    printf("%s\n", configuration_to_string(&conf));

    ret->server_id = conf.server_id;
    conf.server_id = NULL;

    *err = create_connect_sockets(&conf, ret);
    if(*err != DTC_ERR_NONE)
        goto err_exit;

    ret->timeout = conf.timeout;

    if(DTC_ERR_NONE != start_router_socket_handler(ret)) {
        *err = DTC_ERR_INTERN;
        goto err_exit;
        //TODO free connections on error
    }

    free_conf(&conf);

    return ret;

err_exit:
    free(ret);
    free_conf(&conf);
    return NULL;
}

void handle_sign_req(void *zmq_ctx, const struct op_req *req, const char *user,
                     Hash_t *expected_msgs)
{
    struct handle_sign_key_data *sign_key_data;
    Buffer_t *signatures_buffer;
    int ret;
    struct sign_req *sign_req = (struct sign_req *)&req->args->sign_req;

    ht_lock_get(expected_msgs);
    if(!ht_get_element(expected_msgs, sign_req->signing_id,
                       (void **)&sign_key_data)) {
        ht_unlock_get(expected_msgs);
        LOG_DEBUG(LOG_LVL_NOTI, "User %s signing an unexpected key.", user)
        return;
    }

    if(sign_req->status_code != 0) {
        ht_unlock_get(expected_msgs);
        LOG_DEBUG(LOG_LVL_ERRO, "Got a error (%u) from %s when signing.",
                  sign_req->status_code)
        return;
    }

    signatures_buffer = sign_key_data->signatures;
    ret = tc_verify_signature(
            sign_req->signature, sign_key_data->prepared_doc,
            sign_key_data->key_metainfo);
    //TODO is this the right check? Ask Pancho.
    if(!ret) {
        ht_unlock_get(expected_msgs);
        LOG_DEBUG(LOG_LVL_ERRO, "Got a error verifying a key from %s\n",
                  user)
        return;
    }

    ret = put_nowait(signatures_buffer, (void *)sign_req->signature);
    assert(ret == 0);
    // This is needed in order to not free the signature when req is freed.
    sign_req->signature = NULL;
    ht_unlock_get(expected_msgs);
}

void handle_store_key_req(void *zmq_ctx, const struct op_req *req,
                          const char *user, Hash_t *expected_msgs)
{
    struct handle_store_key_data *data;
    struct store_key_res store_key_res;
    struct op_req response;
    key_share_t *key_share;
    uint16_t key_rejected = 0;

    struct store_key_req *store_key_req =
            (struct store_key_req *)&req->args->store_key_req;
    // If key was not accepted.
    if(store_key_req->key_id_accepted != 1) {
        key_rejected = 1;
    }

    response.op = OP_STORE_KEY_RES;
    response.version = 1;
    response.args = (union command_args *)&store_key_res;
    ht_lock_get(expected_msgs);
    if(!ht_get_element(expected_msgs, store_key_req->key_id, (void **)&data)) {
        ht_unlock_get(expected_msgs);
        LOG_DEBUG(LOG_LVL_NOTI, "User %s trying to get a not expected key %s.",
                          user, store_key_req->key_id)
        return;
    }

    if(!uht_add_element(data->users_delivered, user, key_rejected)) {
        ht_unlock_get(expected_msgs);
        LOG_DEBUG(LOG_LVL_CRIT, "User %s trying to get a key more than once ",
                                user)
        return;
    }

    if(get_nowait(data->keys, (void **)&key_share)) {
        ht_unlock_get(expected_msgs);
        LOG_DEBUG(LOG_LVL_CRIT, "Error, not more keys availables")
        return;
    }

    store_key_res.meta_info = data->meta_info;
    store_key_res.key_id = store_key_req->key_id;
    store_key_res.key_share = key_share;

    if(!send_router_msg(zmq_ctx, &response, user)) {
        LOG_DEBUG(LOG_LVL_ERRO, "Error sending msg to %s", user)
        put_nowait(data->keys, key_share);
        uht_get_and_delete_element(data->users_delivered, user, NULL);
    }

    ht_unlock_get(expected_msgs);
    return;
}

void handle_delete_key_share_req(void *zmq_ctx, const struct op_req *req,
                                 const char *user, Hash_t *expected_msgs)
{
    LOG_DEBUG(LOG_LVL_NOTI, "Received a delete confirmation from %s, user")
    return;
}

static void handle_router_rcvd_msg(void *zmq_ctx, zmq_msg_t *msg, int msg_size,
                                   const char *user, Hash_t *tables[OP_MAX])
{
    struct op_req *req = unserialize_op_req(zmq_msg_data(msg), msg_size);
    if(req == NULL) {
        LOG_DEBUG(LOG_LVL_ERRO, "Error unserializing msg from %s", user)
        return;
    }

    if(req->op == OP_STORE_KEY_REQ) {
        handle_store_key_req(zmq_ctx, req, user, tables[OP_STORE_KEY_REQ]);
        delete_op_req(req);
    }
    else if(req->op == OP_DELETE_KEY_SHARE_REQ) {
        handle_delete_key_share_req(zmq_ctx, req, user, tables[req->op]);
        delete_op_req(req);
    }
    else if(req->op == OP_SIGN_REQ) {
        handle_sign_req(zmq_ctx, req, user, tables[req->op]);
    }
    else {
        LOG_DEBUG(LOG_LVL_ERRO, "Not supported operation %d", req->op)
        delete_op_req(req);
    }

    LOG_DEBUG(LOG_LVL_LOG, "TEST: %s", user)
}

void *router_socket_handler(void *data_);

static int start_router_socket_handler(dtc_ctx_t *ctx)
{
    int ret;
    int i;
    void *inproc_socket, *close_thread_socket;
    struct router_socket_handler_data *data;
    inproc_socket = zmq_socket(ctx->zmq_ctx, ZMQ_PULL);
    close_thread_socket = zmq_socket(ctx->zmq_ctx, ZMQ_PAIR);
    pthread_t pid;

    if(inproc_socket == NULL || close_thread_socket == NULL) {
        LOG_DEBUG(LOG_LVL_CRIT, "Not able to create inproc_socket %s",
                  zmq_strerror(errno))
        return DTC_ERR_ZMQ_ERROR;
    }

    ret = zmq_bind(inproc_socket, SEND_ROUTER_INPROC_BINDING);
    if(ret != 0) {
        LOG_DEBUG(LOG_LVL_CRIT, "Not able to bind inproc socket %s",
                  zmq_strerror(errno))
        zmq_close(close_thread_socket);
        zmq_close(inproc_socket);
        return DTC_ERR_ZMQ_ERROR;
    }

    ret = zmq_bind(close_thread_socket, CLOSE_SOCKET_ROUTER_THREAD_BINDING);
    if(ret != 0) {
        LOG_DEBUG(LOG_LVL_CRIT, "Not able to bind inproc socket %s",
                  zmq_strerror(errno))
        zmq_close(close_thread_socket);
        zmq_close(inproc_socket);
        return DTC_ERR_ZMQ_ERROR;
    }

    data = (struct router_socket_handler_data *)malloc(
                                sizeof(struct router_socket_handler_data));
    if(data == NULL) {
        LOG_DEBUG(LOG_LVL_CRIT, "Not enough memory for router_socket_handler")
        zmq_close(inproc_socket);
        zmq_close(close_thread_socket);
        return DTC_ERR_NOMEM;
    }

    data->zmq_ctx = ctx->zmq_ctx;
    data->inproc_socket = inproc_socket;
    data->router_socket = ctx->router_socket;
    data->close_thread_socket = close_thread_socket;

    for(i = 0; i < OP_MAX; i++)
        data->expected_msgs[i] = ctx->expected_msgs[i] = ht_init_hashtable();

    ret = pthread_create(&pid, NULL, router_socket_handler, (void *)data);
    if(ret != 0) {
        LOG_DEBUG(LOG_LVL_CRIT, "Failed creating pthread.")
        zmq_close(inproc_socket);
        zmq_close(close_thread_socket);
        return DTC_ERR_INTERN;
    }

    ctx->router_socket_thr_pid = pid;
    return DTC_ERR_NONE;
}

// The router thread must be used by this and only by this thread.
void *router_socket_handler(void *data_)
{
    int rc;
    zmq_msg_t msg_, out_msg_;
    zmq_msg_t *msg = &msg_;
    zmq_msg_t *out_msg = &out_msg_;
    zmq_pollitem_t items[3];
    int poll_timeout = -1;
    char *user, *aux;
    struct router_socket_handler_data *data =
            (struct router_socket_handler_data *)data_;

    items[0].socket = data->router_socket;
    items[1].socket = data->inproc_socket;
    items[2].socket = data->close_thread_socket;
    items[0].events = items[1].events = items[2].events = ZMQ_POLLIN;
    while(1) {
        rc = zmq_poll(items, 3, poll_timeout);
        if(rc == 0) // Exit
            break;
        if(rc < 0) {
            LOG_DEBUG(LOG_LVL_LOG, "Poll failed:%s", zmq_strerror(errno))
            break;
        }
        // Router received a msg.
        if(items[0].revents) {

            user = s_recv(data->router_socket);
            if(user == NULL) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error getting user.")
                continue;
            }

            rc = zmq_msg_init(msg);
            if(rc != 0) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error initializing msg")
                free(user);
                continue;
            }

            rc = zmq_msg_recv(msg, data->router_socket, 0);
            if(rc == -1) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error receiving msg")
                free(user);
                zmq_msg_close(msg);
                continue;
            }
            handle_router_rcvd_msg(data->zmq_ctx, msg, rc, user,
                                   data->expected_msgs);
            free(user);
            zmq_msg_close(msg);
        }
        // Inproc socket rcvd a message to be sent using the router socket.
        if(items[1].revents) {
            rc = zmq_msg_init(msg);
            if(rc != 0) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error initializing msg")
                continue;
            }
            rc = zmq_msg_init(out_msg);
            if(rc != 0) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error initializing msg")
                zmq_close(msg);
                continue;
            }

            user = s_recv(data->inproc_socket);
            if(user == NULL) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error getting user.")
                zmq_close(msg);
                zmq_close(out_msg);
                continue;
            }

            rc = zmq_msg_recv(msg, data->inproc_socket, 0);
            if(rc == -1) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error receiving msg")
                free(user);
                zmq_close(msg);
                zmq_close(out_msg);
                continue;
            }

            rc = zmq_msg_copy(out_msg, msg);
            zmq_msg_close(msg);
            if(rc != 0) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error copying msg")
                free(user);
                zmq_msg_close(out_msg);
                continue;
            }

            rc = s_sendmore(data->router_socket, user);
            free(user);
            if(rc == -1) {
                LOG_DEBUG(LOG_LVL_ERRO, "Error sending msg router socket.")
                zmq_msg_close(out_msg);
                continue;
            }

            rc = zmq_msg_send(out_msg, data->router_socket, 0);
            if(rc == -1) {
                zmq_msg_close(out_msg);
                continue;
            }
        }
        if(items[2].revents) {
            aux = s_recv(data->close_thread_socket);
            if(aux)
                free(aux);
            poll_timeout = 0;
        }
    }
    LOG_DEBUG(LOG_LVL_LOG, "Closing router_socket_handler thread")
    zmq_close(data->inproc_socket);
    zmq_close(data->close_thread_socket);
    zmq_close(data->router_socket);
    free(data);
    return NULL;
}


int dtc_generate_key_shares(dtc_ctx_t *ctx, const char *key_id, size_t bit_size,
                            uint16_t threshold, uint16_t cant_nodes,
                            key_metainfo_t **key_metainfo)
{
    key_share_t **key_shares = NULL;
    int ret;

    key_shares = tc_generate_keys(key_metainfo, bit_size, threshold,
                                  cant_nodes);
    if(!key_shares)
        return DTC_ERR_INTERN;

    ret = store_key_shares_nodes(ctx, key_id, cant_nodes, key_metainfo, key_shares);
    if(ret != DTC_ERR_NONE) {
        dtc_delete_key_shares(ctx, key_id);
    }

    tc_clear_key_shares(key_shares, *key_metainfo);
    return ret;

}

static int store_key_shares_nodes(dtc_ctx_t *ctx, const char *key_id,
                                  uint16_t cant_nodes,
                                  key_metainfo_t **key_metainfo,
                                  key_share_t **key_shares)
{
    struct op_req pub_op;
    struct store_key_pub store_key_pub;
    struct handle_store_key_data store_key_data;
    union command_args *args = (union command_args *) &store_key_pub;
    int ret, i;
    void *remaining_key;
    unsigned prev;
    uint16_t val;
    Buffer_t *keys;

    pub_op.version = 1;
    pub_op.op = OP_STORE_KEY_PUB;
    store_key_pub.server_id = ctx->server_id;
    store_key_pub.key_id = key_id;
    pub_op.args = args;

    keys = newBuffer(cant_nodes);
    if(!keys)
        return DTC_ERR_NOMEM;

    store_key_data.meta_info = *key_metainfo;
    store_key_data.keys = keys;
    store_key_data.users_delivered = uht_init_hashtable();

    ret = ht_add_element(ctx->expected_msgs[OP_STORE_KEY_REQ],
                         key_id, (void *)&store_key_data);
    if(ret == 0) {
        free_buffer(keys);
        uht_free(store_key_data.users_delivered);
        return DTC_ERR_INVALID_VAL;
    }

    for(i = 0; i < cant_nodes; i++)
        put(keys, (void *)key_shares[i]);

    ret = send_pub_op(&pub_op, ctx->pub_socket);
    if(ret != DTC_ERR_NONE) {
        ht_get_and_delete_element(ctx->expected_msgs[OP_STORE_KEY_REQ],
                                  key_id, NULL);
        //To free the buffer it must be empty.
        while(get_nowait(keys, (void **)&remaining_key) == 0)
            ;
        free_buffer(keys);
        uht_free(store_key_data.users_delivered);
        return ret;
    }

    if(wait_until_empty(keys, ctx->timeout)) {
        //TODO on timeout
        ;
    }

    ret = ht_get_and_delete_element(ctx->expected_msgs[OP_STORE_KEY_REQ],
                                    key_id, NULL);
    if(ret != 1) {
        while(get_nowait(keys, (void **)&remaining_key) == 0)
            ;
        free_buffer(keys);
        uht_free(store_key_data.users_delivered);
        return DTC_ERR_INTERN;
    }

    ret = DTC_ERR_NONE;
    while(get_nowait(keys, (void **)&remaining_key) == 0)
        ret = DTC_ERR_INTERN;
    free_buffer(keys);

    if(ret != DTC_ERR_NONE)
        uht_free(store_key_data.users_delivered);

    //Check that all the nodes did accept the key.
    prev = 0;
    while(uht_next(store_key_data.users_delivered, &prev, NULL, &val))
        if(val != 0)
            ret = DTC_ERR_INVALID_VAL;

    uht_free(store_key_data.users_delivered);

    return ret;
}

void dtc_delete_key_shares(dtc_ctx_t *ctx, const char *key_id)
{
    struct op_req pub_op;
    struct delete_key_share_pub delete_key_share;

    pub_op.args = (union command_args *) &delete_key_share;
    pub_op.version = 1;
    pub_op.op = OP_DELETE_KEY_SHARE_PUB;

    delete_key_share.key_id = key_id;

    send_pub_op(&pub_op, ctx->pub_socket);
}

int dtc_sign(dtc_ctx_t *ctx, const key_metainfo_t *key_metainfo,
             const char *key_id, bytes_t *message, bytes_t **out)
{
    struct op_req pub_op;
    struct sign_pub sign_pub;
    int ret, i = 0;
    char signing_id[37];
    int threshold = tc_key_meta_info_k(key_metainfo);
    int cant_nodes = tc_key_meta_info_l(key_metainfo);
    struct handle_sign_key_data sign_key_data;
    signature_share_t *signature;
    Buffer_t *signatures_buffer;
    signature_share_t *signatures[cant_nodes];
    bytes_t *prepared_doc = tc_prepare_document(
            message, TC_SHA256, key_metainfo);

    get_uuid_as_char(signing_id);

    pub_op.args = (union command_args *) &sign_pub;
    pub_op.version = 1;
    pub_op.op = OP_SIGN_PUB;

    sign_pub.signing_id = signing_id;
    sign_pub.key_id = key_id;
    sign_pub.message = (uint8_t *)prepared_doc->data;
    sign_pub.msg_len = prepared_doc->data_len;

    signatures_buffer = newBuffer(cant_nodes);

    sign_key_data.signatures = signatures_buffer;
    sign_key_data.prepared_doc = prepared_doc;
    sign_key_data.key_metainfo = key_metainfo;

    ret = ht_add_element(ctx->expected_msgs[OP_SIGN_REQ], signing_id,
                         (void *)&sign_key_data);
    if(ret == 0) {
        free_buffer(signatures_buffer);
        return DTC_ERR_INTERN;
    }

    ret = send_pub_op(&pub_op, ctx->pub_socket);
    if(ret != DTC_ERR_NONE) {
        LOG_DEBUG(LOG_LVL_CRIT, "Send pub msg error")
        return ret;
    }

    ret = wait_n_elements(signatures_buffer, threshold, ctx->timeout);
    assert(1 == ht_get_and_delete_element(ctx->expected_msgs[OP_SIGN_REQ],
                                          signing_id, NULL));
    // Returned on timeout.
    if(ret == 0) {
        //TODO
        ;
    }

    while(get_nowait(signatures_buffer, (void **)&signature) == 0)
        signatures[i++] = (signature_share_t *)signature;

    tc_join_signatures((const signature_share_t **)signatures, prepared_doc,
                       key_metainfo);



    //signature = wait_signatures();
    //TODO
    return 0;
}

int dtc_destroy(dtc_ctx_t *ctx)
{
    int i;
    if(!ctx)
        return DTC_ERR_NONE;
    zmq_close(ctx->pub_socket);

    if(!close_router_thread(ctx->zmq_ctx)){
        zmq_ctx_shutdown(ctx->zmq_ctx);
    }

    pthread_join(ctx->router_socket_thr_pid, NULL);

    zmq_ctx_term(ctx->zmq_ctx);
    for(i = 0; i < OP_MAX; i++)
        ht_free(ctx->expected_msgs[i]);

    free(ctx->server_id);
    free(ctx);

    return DTC_ERR_NONE;
}

static int close_router_thread(void *zmq_ctx)
{
    void *sock = zmq_socket(zmq_ctx, ZMQ_PAIR);
    int ret;
    if(!sock)
        return 0;
    if(zmq_connect(sock, CLOSE_SOCKET_ROUTER_THREAD_BINDING) != 0) {
        zmq_close(sock);
        return 0;
    }

    ret = s_send(sock, "Die") > 0;
    zmq_close(sock);

    return ret;
}

static int send_pub_op(struct op_req *pub_op, void *socket)
{
    size_t msg_size = 0;
    char *msg_data = NULL;
    int ret;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;

    msg_size = serialize_op_req(pub_op, &msg_data);
    if(!msg_size) {
        LOG_DEBUG(LOG_LVL_CRIT, "Serialize error")
        return DTC_ERR_SERIALIZATION;
    }

    ret = zmq_msg_init_data(msg, msg_data, msg_size, free_wrapper, free);
    if(ret) {
        LOG_DEBUG(LOG_LVL_CRIT, "zmq_msg_init_data: %s", zmq_strerror(errno))
        free(msg_data);
        return DTC_ERR_INTERN;
    }

    //TODO sockets are not thread safe, a mutex should be used here if we want
    //to accept calls from different threads.
    ret = zmq_msg_send(msg, socket, 0);
    if(ret == 1) {
        LOG_DEBUG(LOG_LVL_CRIT, "Error sending the msg: %s", zmq_strerror(errno))
        zmq_msg_close(msg);
        return DTC_ERR_COMMUNICATION;
    }

    return DTC_ERR_NONE;
}

static int create_connect_sockets(const struct configuration *conf,
                                  struct dtc_ctx *ctx)
{
    void *pub_socket, *router_socket;
    int ret_val = 0;
    int i = 0;
    char *protocol = "tcp";
    const int BUFF_SIZE = 200;
    char buff[BUFF_SIZE];
    int ret = DTC_ERR_NONE;

    void *zmq_ctx = zmq_ctx_new();
    if(!zmq_ctx) {
        LOG_DEBUG(LOG_LVL_CRIT, "Context initialization error.");
        return DTC_ERR_ZMQ_ERROR;
    }

    pub_socket = zmq_socket(zmq_ctx, ZMQ_PUB);
    if(!pub_socket) {
        LOG_DEBUG(LOG_LVL_CRIT, "Unable to create pub socket %s.",
                  zmq_strerror(errno));
        return DTC_ERR_ZMQ_ERROR;
    }

    router_socket = zmq_socket(zmq_ctx, ZMQ_ROUTER);
    if(!router_socket) {
        LOG_DEBUG(LOG_LVL_CRIT, "Unable to create router socket.");
        return DTC_ERR_ZMQ_ERROR;
    }

    ret = set_client_socket_security(pub_socket, conf->private_key,
                                     conf->public_key);
    if(ret)
        goto err_exit;

    ret = set_client_socket_security(router_socket, conf->private_key,
                                     conf->public_key);
    if(ret)
        goto err_exit;
    ret_val = zmq_setsockopt(router_socket, ZMQ_IDENTITY, ctx->server_id,
                             strlen(ctx->server_id));
    if(ret_val != 0) {
        ret = DTC_ERR_ZMQ_CURVE;
        goto err_exit;
    }
    for(i = 0; i < conf->cant_nodes; i++) {
    //for(i = conf->cant_nodes -1; i >= 0; i--) {
        ret_val = zmq_setsockopt(pub_socket, ZMQ_CURVE_SERVERKEY,
                                 conf->nodes[i].public_key,
                                 strlen(conf->nodes[i].public_key));
        if(ret_val) {
            LOG_DEBUG(LOG_LVL_CRIT,
                      "PUB socket: Error setting node %d public key: %s.", i,
                      strerror(errno));
            return DTC_ERR_ZMQ_CURVE;
        }

        ret_val = zmq_setsockopt(router_socket, ZMQ_CURVE_SERVERKEY,
                                 conf->nodes[i].public_key,
                                 strlen(conf->nodes[i].public_key));
        if(ret_val) {
            LOG_DEBUG(LOG_LVL_CRIT,
                      "ROUTER socket: Error setting node %d public key: %s.", i,
                      strerror(errno));
            return DTC_ERR_ZMQ_CURVE;
        }

        ret_val = snprintf(&buff[0], BUFF_SIZE, "%s://%s:%" PRIu16,
                           protocol, conf->nodes[i].ip,
                           conf->nodes[i].sub_port);
        if(ret_val >= BUFF_SIZE) {
            LOG_DEBUG(LOG_LVL_CRIT, "BUFF_SIZE %d is not enough to store %d",
                      BUFF_SIZE, ret_val);
            ret = DTC_ERR_INTERN;
            goto err_exit;
        }

        ret_val = zmq_connect(pub_socket, &buff[0]);
        if(ret_val) {
            LOG_DEBUG(LOG_LVL_CRIT, "Error connecting pub_socket to %s.", &buff[0]);
            ret = DTC_ERR_CONNECTION;
            goto err_exit;
        }
        LOG_DEBUG(LOG_LVL_NOTI, "PUB socket connected to %s", &buff[0]);

        ret_val = snprintf(&buff[0], BUFF_SIZE, "%s://%s:%" PRIu16,
                           protocol, conf->nodes[i].ip,
                           conf->nodes[i].dealer_port);
        if(ret_val >= BUFF_SIZE) {
            LOG_DEBUG(LOG_LVL_CRIT, "BUFF_SIZE %d is not enough to store %d",
                      BUFF_SIZE, ret_val);
            ret = DTC_ERR_INTERN;
            goto err_exit;
        }

        ret_val = zmq_connect(router_socket, &buff[0]);
        if(ret_val) {
            LOG_DEBUG(LOG_LVL_CRIT, "Error connecting router_socket to %s.",
                      &buff[0]);
            ret = DTC_ERR_CONNECTION;
            goto err_exit;
        }
        LOG_DEBUG(LOG_LVL_NOTI, "ROUTER socket connected to %s", &buff[0]);
    }

    ctx->zmq_ctx = zmq_ctx;
    ctx->pub_socket = pub_socket;
    ctx->router_socket = router_socket;

    return ret;

err_exit:
    zmq_close(pub_socket);
    zmq_close(router_socket);
    zmq_ctx_destroy(zmq_ctx);
    return ret;
}

static int set_client_socket_security(void *socket,
                                      const char *client_secret_key,
                                      const char *client_public_key)
{
    int rc = 0;

    rc = zmq_setsockopt(socket, ZMQ_CURVE_PUBLICKEY, client_public_key,
                        strlen(client_public_key));
    if(rc) {
        LOG_DEBUG(LOG_LVL_CRIT, "Error setting the client's public key: %s.",
                  strerror(errno));
        return DTC_ERR_ZMQ_CURVE;
    }

    rc = zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY, client_secret_key,
                        strlen(client_secret_key));
    if(rc) {
        LOG_DEBUG(LOG_LVL_CRIT, "Error setting the client's secret key: %s.",
                  strerror(errno));
        return DTC_ERR_ZMQ_CURVE;
    }

    return 0;
}

/**
 * Read the configuration file an load its definitions into conf.
 *
 * @param conf Configuration struct to load the data into.
 *
 * @return DTC_ERR_NONE on success, a proper error code on error.
 *
 **/
static int read_configuration_file(struct configuration *conf)
{
    config_t cfg;
    config_setting_t *root, *master, *nodes, *element;
    int cant_nodes = 0, rc;
    unsigned int i = 0;
    int ret = DTC_ERR_CONFIG_FILE;

    config_init(&cfg);

    if(!config_read_file(&cfg, conf->configuration_file)) {
        LOG_DEBUG(LOG_LVL_CRIT, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
        goto err_exit;
    }

    root = config_root_setting(&cfg);
    master = config_setting_get_member(root, "master");
    if(!master){
        LOG_DEBUG(LOG_LVL_CRIT, "master was not found in the conf file %s",
            conf->configuration_file);
        goto err_exit;
    }

    nodes = config_setting_get_member(master, "nodes");
    if(!nodes) {
        LOG_DEBUG(LOG_LVL_CRIT, "nodes not specified in master configuration");
        goto err_exit;
    }

    cant_nodes = config_setting_length(nodes);
    if(cant_nodes == 0) {
        LOG_DEBUG(LOG_LVL_CRIT, "0 nodes specified for master");
        goto err_exit;
    }

    conf->cant_nodes = cant_nodes;
    conf->nodes =
            (struct node_info *) malloc(sizeof(struct node_info) * cant_nodes);
    if(conf->nodes == NULL) {
        ret = DTC_ERR_NOMEM;
        goto err_exit;
    }

    ret = lookup_string_conf_element(master, "public_key", &conf->public_key);
    if(ret != DTC_ERR_NONE)
        goto err_exit;

    ret = lookup_string_conf_element(master, "private_key", &conf->private_key);
    if(ret != DTC_ERR_NONE)
        goto err_exit;

    ret = lookup_string_conf_element(master, "server_id", &conf->server_id);
    if(ret != DTC_ERR_NONE)
        goto err_exit;

    rc = lookup_uint16_conf_element(master, "timeout", &conf->timeout);
    if(rc != DTC_ERR_NONE) {
        LOG_DEBUG(LOG_LVL_NOTI,
                  "Error reading timeout from config, using default:%" PRIu16,
                  DEFAULT_TIMEOUT);
        conf->timeout = DEFAULT_TIMEOUT;
    }

    for(i = 0; i < cant_nodes; i++) {
        conf->nodes[i].ip = NULL;
        element = config_setting_get_elem(nodes, i);
        if(element == NULL) {
            LOG_DEBUG(LOG_LVL_CRIT, "Error getting element %u from nodes.", i);
            goto err_exit;
        }

        ret = lookup_string_conf_element(element, "ip", &conf->nodes[i].ip);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

        ret = lookup_string_conf_element(element, "public_key",
                                         &conf->nodes[i].public_key);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

        ret = lookup_uint16_conf_element(element, "sub_port",
                                         &conf->nodes[i].sub_port);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

        ret = lookup_uint16_conf_element(element, "dealer_port",
                                         &conf->nodes[i].dealer_port);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

    }

    config_destroy(&cfg);

    return DTC_ERR_NONE;

err_exit:
    free_nodes(cant_nodes, conf->nodes);
    cant_nodes = 0;
    config_destroy(&cfg);
    return ret;
}
