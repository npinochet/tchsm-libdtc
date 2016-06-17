#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <libconfig.h>
#include <zmq.h>

#include <tc.h>

#include "include/dtc.h"
#include "messages.h"
#include "structs.h"
#include "utilities.h"

//TODO change this to const char* ?
#define SEND_ROUTER_INPROC_BINDING "inproc://send_router"
#define CLOSE_SOCKET_ROUTER_THREAD_BINDING "inproc://close_router_thread"
#define ZMQ_MONITOR_PUB_SOCKET "inproc://monitor_pub"
#define ZMQ_MONITOR_ROUTER_SOCKET "inproc://monitor_router"

#define PRINT_CONFIGURATION_BUFF_SIZE 500

const uint16_t DEFAULT_TIMEOUT = 10;

struct dtc_ctx {

    const char *instance_id;

    // Timeout for the operations.
    uint16_t timeout;

    // Communication
    void *zmq_ctx;
    void *pub_socket;
    void *router_socket;

    // Thread to protect pub_socket, as zmq sockets are not thread safe.
    pthread_mutex_t pub_socket_mutex;
    //Router socket thread
    pthread_t router_socket_thr_pid;
    //Monitoring thread pid;
    pthread_t monitoring_thr_pid;

    Hash_t *expected_msgs[OP_MAX];
};

struct router_socket_handler_data {
    void *zmq_ctx;
    void *router_socket;
    void *inproc_socket;
    void *close_thread_socket;
    Hash_t *expected_msgs[OP_MAX];
};

struct monitoring_thread_data {
    void **monitors;
    const char **monitors_names;
    int monitors_cant;
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
    Uint16_Hash_t *user_already_signed;
};

static void free_nodes(unsigned int nodes_cant, struct node_info *node)
{
    unsigned int i;
    if(!node)
        return;
    for(i = 0; i < nodes_cant; i++) {
        if(node[i].ip)
            free((void *)node[i].ip);
    }
    free(node);
}

void divide_timeout(uint16_t ctx_timeout, unsigned retries,
                    unsigned *timeout_secs, unsigned *timeout_usecs)
{
    double timeout = ((double)ctx_timeout) / retries;
    *timeout_secs = (unsigned)timeout;
    *timeout_usecs = (timeout - *timeout_secs) * 1000000; // Secs to microsecs
}

/* Return a human readable version of the dtc_configuration */
static char* configuration_to_string(const struct dtc_configuration *conf)
{
    /* Be aware, this memory is shared among the aplication, this function
     * should be called just once or the memory of the previous calls might get
     * corrupted.
     */
    static char buff[PRINT_CONFIGURATION_BUFF_SIZE];
    int space_left = PRINT_CONFIGURATION_BUFF_SIZE;
    unsigned int i;

    space_left -= snprintf(buff, space_left,
                           "Timeout:\t\t%" PRIu16 "\n"
                           "Server id:\t\t%s\nNodes:",
                           conf->timeout, conf->instance_id);

    for(i = 0; i < conf->nodes_cant; i++) {
        space_left -= snprintf(
                        buff + (PRINT_CONFIGURATION_BUFF_SIZE - space_left),
                        space_left, "\n\t\t\t%s:{%" PRIu16 ",%" PRIu16 "}",
                        conf->nodes[i].ip, conf->nodes[i].sub_port,
                        conf->nodes[i].dealer_port);
        if(space_left <= 0) {
            LOG(LOG_LVL_ERRO, "Not enough space in the buff to dump the conf");
            break;
        }
    }

    return &buff[0];
}


static int get_monitor_event(void *monitor, uint16_t *event,
                             uint32_t *event_value, char **address)
{
    zmq_msg_t msg;
    uint8_t *data;
    size_t size;

    zmq_msg_init(&msg);

    if(zmq_msg_recv(&msg, monitor, 0) == -1) {
        LOG(LOG_LVL_CRIT, "LOG_ERR, Monitor thread recv error %s",
            zmq_strerror(errno));
        zmq_msg_close(&msg);
        return -1;
    }

    data = (uint8_t *)zmq_msg_data(&msg);
    if(event)
        *event = *(uint16_t *)data;
    if(event_value)
        *event_value = *(uint32_t *)(data + 2);

    zmq_msg_close(&msg);
    zmq_msg_init(&msg);

    if(zmq_msg_recv(&msg, monitor, 0) == -1) {
        LOG(LOG_LVL_CRIT, "LOG_ERR, Monitor thread recv error %s",
            zmq_strerror(errno));
        zmq_msg_close(&msg);
        return -1;
    }

    if(address) {
        data = (uint8_t *)zmq_msg_data(&msg);
        size = zmq_msg_size(&msg);
        *address = (char *)malloc(size + 1);
        memcpy(*address, data, size);
        *address[size] = '\0';
    }

    zmq_msg_close(&msg);

    return 1;
}

static void *monitoring_thread(void *data_)
{
    int i, it;
    int rc;
    uint16_t event;
    uint32_t event_value;
    char *address;

    struct monitoring_thread_data *data =
            (struct monitoring_thread_data *)data_;
    void **monitors = data->monitors;
    const char **monitors_names = data->monitors_names;
    int monitors_cant = data->monitors_cant;
    int poll_items = monitors_cant;

    zmq_pollitem_t items[poll_items];
    for(i = 0; i < poll_items; i++) {
        items[i].socket = monitors[i];
        items[i].events = ZMQ_POLLIN;
    }

    while(1) {
        rc = zmq_poll(items, poll_items, -1);
        if(rc == -1) {
            break;
        }

        for(i = 0; i < poll_items; i++)
            if(items[i].revents)
                it = i;

        rc = get_monitor_event(monitors[it], &event, &event_value, &address);
        if(rc != 1) {
            LOG(LOG_LVL_ERRO, "Error getting monitor event");
            continue;
        }

        LOG(LOG_LVL_INFO, "Event %d with value %d received at %s", event,
            event_value, address);
        free(address);
    }

    for(i = 0; i < monitors_cant; i++)
        zmq_close(monitors[i]);

    free(monitors);
    free(monitors_names);
    free(data_);
    LOG(LOG_LVL_INFO, "Closing monitoring thread");

    return NULL;
}

int wait_n_connections(void **monitors, int monitors_cant,
                              int expected_connections, int timeout)
{
    zmq_msg_t msg;
    char *data, *address;
    size_t size;
    uint16_t event;
    uint16_t *event_ptr;
    int remaining_connections[monitors_cant];
    Uint16_Hash_t *connected[monitors_cant];
    int rc, i, it, poll_items = monitors_cant;
    zmq_pollitem_t items[monitors_cant];
    struct timeval before, now;
    long elapsed_milisecs;

    for(i = 0; i < monitors_cant; i ++) {
        remaining_connections[i] = expected_connections;
        items[i].socket = monitors[i];
        items[i].events = ZMQ_POLLIN;
        connected[i] = uht_init_hashtable();
    }

    while(1) {
        for(i = 0; i < monitors_cant; i++)
            if(remaining_connections[i] > 0)
                break;
        if(i == monitors_cant)
            break;

        gettimeofday(&before, NULL);
        rc = zmq_poll(items, poll_items, timeout);
        if(rc == 0)
            break;
        if(rc < 0) {
            LOG(LOG_LVL_CRIT, "Poll failed: %s", zmq_strerror(errno));
            break;
        }
        gettimeofday(&now, NULL);
        elapsed_milisecs = ((now.tv_sec - before.tv_sec) * 1000) +
                           ((now.tv_usec - before.tv_usec) / 1000.0);
        timeout -= elapsed_milisecs;
        if(timeout <= 0)
            break;

        for(i = 0; i < poll_items; i++)
            if(items[i].revents)
                it = i;
        zmq_msg_init(&msg);
        if(zmq_msg_recv(&msg, monitors[it], 0) == -1)
            break;

        event_ptr = (uint16_t *)zmq_msg_data(&msg);
        event = *event_ptr;

        //TODO Is the value relevant?
        //if(value)
        //    *value = *(uint32_t)(event_ptr + 1);

        zmq_msg_close(&msg);
        zmq_msg_init(&msg);

        if(zmq_msg_recv(&msg, monitors[it], 0) == -1)
            break;

        if(event != ZMQ_EVENT_CONNECTED) {
            zmq_msg_close(&msg);
            continue;
        }

        data = (char *)zmq_msg_data(&msg);
        size = zmq_msg_size(&msg);
        address = (char *)malloc(size + 1);
        address[size] = 0;
        memcpy(address, data, size);
        LOG(LOG_LVL_NOTI, "Connection stablished with %s", address);
        if(uht_add_element(connected[it], address, 1))
            remaining_connections[it]--;
        zmq_msg_close(&msg);
        free(address);
    }

    uht_free(connected[0]);
    uht_free(connected[1]);

    if(timeout <= 0|| rc == 0)
        return DTC_ERR_TIMED_OUT;
    if(remaining_connections[0] == 0 && remaining_connections[1] == 0) {
        return DTC_ERR_NONE;
    }
    return DTC_ERR_INTERN;
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
        LOG(LOG_LVL_ERRO, "zmq_socket:%s", zmq_strerror(errno));
        return 0;
    }

    ret = zmq_connect(sock, SEND_ROUTER_INPROC_BINDING);
    if(ret != 0) {
        LOG(LOG_LVL_ERRO, "zmq_connect:%s", zmq_strerror(errno));
        goto err_exit;
    }

    msg_size = serialize_op_req(op, &serialized_msg);
    if(!msg_size) {
        LOG(LOG_LVL_ERRO, "Serialization at send_router_msg");
        goto err_exit;
    }

    ret = zmq_msg_init_data(msg, serialized_msg, msg_size, free_wrapper, free);
    if(ret) {
        LOG(LOG_LVL_ERRO, "Unable to init msg: %s", zmq_strerror(errno));
        free(serialized_msg);
        goto err_exit;
    }

    ret = s_sendmore(sock, user);
    if(ret == 0) {
        LOG(LOG_LVL_ERRO, "Not able to send user");
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

static int set_client_socket_security(void *socket,
                                      const char *client_secret_key,
                                      const char *client_public_key);
static int create_connect_sockets(const struct dtc_configuration *conf,
                                  struct dtc_ctx *ctx);
static int read_configuration_file(const char *conf_file_path,
                                   struct dtc_configuration *conf);
static int send_pub_op(dtc_ctx_t *ctx, struct op_req *pub_op);
static int start_router_socket_handler(dtc_ctx_t *ctx);
static int close_router_thread(void *zmq_ctx);
static int store_key_shares_nodes(dtc_ctx_t *ctx, const char *key_id,
                                  uint16_t nodes_cant,
                                  key_metainfo_t **key_metainfo,
                                  key_share_t **key_shares);

dtc_ctx_t *dtc_init_from_struct(const struct dtc_configuration *conf, int *err)
{
    int error;

    if(!err)
        err = &error;

    *err = DTC_ERR_NONE;

    dtc_ctx_t *ret = (dtc_ctx_t *) malloc(sizeof(dtc_ctx_t));
    if(!ret) {
        *err = DTC_ERR_NOMEM;
        return NULL;
    }

    if(pthread_mutex_init(&ret->pub_socket_mutex, NULL) != 0) {
        *err = DTC_ERR_INTERN;
        return NULL;
    }

    ret->instance_id = strdup(conf->instance_id);
    ret->timeout = conf->timeout;

    *err = create_connect_sockets(conf, ret);
    if(*err != DTC_ERR_NONE)
        return NULL;

    if(DTC_ERR_NONE != start_router_socket_handler(ret)) {
        *err = DTC_ERR_INTERN;
        zmq_close(ret->pub_socket);
        zmq_close(ret->router_socket);
        zmq_ctx_term(ret->zmq_ctx);
        return NULL;
    }

    return ret;
}

dtc_ctx_t *dtc_init(const char *config_file, int *err)
{
    int error;
    struct dtc_configuration conf;
    dtc_ctx_t *ret;

    if(!err)
        err = &error;

    *err = read_configuration_file(config_file, &conf);
    if(*err != DTC_ERR_NONE)
        return NULL;
    LOG(LOG_LVL_DEBG, "%s\n", configuration_to_string(&conf));

    ret = dtc_init_from_struct(&conf, err);

    memset((void *) &conf, 0, sizeof(struct dtc_configuration));

    return ret;
}

void handle_sign_req(void *zmq_ctx, const struct op_req *req, const char *user,
                     Hash_t *expected_msgs)
{
    struct handle_sign_key_data *sign_key_data;
    Buffer_t *signatures_buffer;
    int ret;
    struct sign_req *sign_req = (struct sign_req *)&req->args->sign_req;

    if(sign_req->status_code != 0) {
        LOG(LOG_LVL_ERRO, "Got an error (%u) from %s when signing.",
                  sign_req->status_code, user);
        return;
    }

    ht_lock_get(expected_msgs);
    if(!ht_get_element(expected_msgs, sign_req->signing_id,
                       (void **)&sign_key_data)) {
        ht_unlock_get(expected_msgs);
        LOG(LOG_LVL_NOTI, "User %s signing an unexpected key.", user);
        return;
    }

    //
    if(!uht_add_element(sign_key_data->user_already_signed, user, 1)){
        //The user already signed this signing_id
        ht_unlock_get(expected_msgs);
        //TODO delete this LOG
        LOG(LOG_LVL_INFO, "User %s already signed this", user);
        return;
    }

    signatures_buffer = sign_key_data->signatures;
    ret = tc_verify_signature(
            sign_req->signature, sign_key_data->prepared_doc,
            sign_key_data->key_metainfo);
    if(ret != 1) {
        ht_unlock_get(expected_msgs);
        LOG(LOG_LVL_ERRO, "Got an error (%d) verifying a key from %s\n",
                  ret, user);
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
        LOG(LOG_LVL_NOTI, "User %s trying to get a not expected key %s.",
                          user, store_key_req->key_id);
        return;
    }

    if(!uht_add_element(data->users_delivered, user, key_rejected)) {
        ht_unlock_get(expected_msgs);
        LOG(LOG_LVL_CRIT, "User %s trying to get a key more than once ",
                                user);
        return;
    }

    if(get_nowait(data->keys, (void **)&key_share)) {
        ht_unlock_get(expected_msgs);
        LOG(LOG_LVL_CRIT, "Error, not more keys availables");
        return;
    }

    store_key_res.meta_info = data->meta_info;

    store_key_res.key_id = store_key_req->key_id;
    store_key_res.key_share = key_share;

    if(!send_router_msg(zmq_ctx, &response, user)) {
        LOG(LOG_LVL_ERRO, "Error sending msg to %s", user);
        put_nowait(data->keys, key_share);
        uht_get_and_delete_element(data->users_delivered, user, NULL);
    }

    ht_unlock_get(expected_msgs);
    return;
}

void handle_delete_key_share_req(void *zmq_ctx, const struct op_req *req,
                                 const char *user, Hash_t *expected_msgs)
{
    LOG(LOG_LVL_NOTI, "Received a delete confirmation from %s", user);
    return;
}

static void handle_router_rcvd_msg(void *zmq_ctx, zmq_msg_t *msg, int msg_size,
                                   const char *user, Hash_t *tables[OP_MAX])
{
    struct op_req *req = unserialize_op_req(zmq_msg_data(msg), msg_size);
    if(req == NULL) {
        LOG(LOG_LVL_ERRO, "Error unserializing msg from %s", user);
        return;
    }

    LOG(LOG_LVL_INFO, "Received at router socket:%d %s", req->op, user);

    if(req->op == OP_STORE_KEY_REQ) {
        handle_store_key_req(zmq_ctx, req, user, tables[OP_STORE_KEY_REQ]);
    }
    else if(req->op == OP_DELETE_KEY_SHARE_REQ) {
        handle_delete_key_share_req(zmq_ctx, req, user, tables[req->op]);
    }
    else if(req->op == OP_SIGN_REQ) {
        handle_sign_req(zmq_ctx, req, user, tables[req->op]);
    }
    else {
        LOG(LOG_LVL_ERRO, "Not supported operation %d", req->op);
    }
    delete_op_req(req);

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
        LOG(LOG_LVL_CRIT, "Not able to create inproc_socket %s",
                  zmq_strerror(errno));
        return DTC_ERR_ZMQ_ERROR;
    }

    ret = zmq_bind(inproc_socket, SEND_ROUTER_INPROC_BINDING);
    if(ret != 0) {
        LOG(LOG_LVL_CRIT, "Not able to bind inproc socket %s",
                  zmq_strerror(errno));
        zmq_close(close_thread_socket);
        zmq_close(inproc_socket);
        return DTC_ERR_ZMQ_ERROR;
    }

    ret = zmq_bind(close_thread_socket, CLOSE_SOCKET_ROUTER_THREAD_BINDING);
    if(ret != 0) {
        LOG(LOG_LVL_CRIT, "Not able to bind inproc socket %s",
                  zmq_strerror(errno));
        zmq_close(close_thread_socket);
        zmq_close(inproc_socket);
        return DTC_ERR_ZMQ_ERROR;
    }

    data = (struct router_socket_handler_data *)malloc(
                                sizeof(struct router_socket_handler_data));
    if(data == NULL) {
        LOG(LOG_LVL_CRIT, "Not enough memory for router_socket_handler");
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
        LOG(LOG_LVL_CRIT, "Failed creating pthread.");
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
            LOG(LOG_LVL_INFO, "Poll failed:%s", zmq_strerror(errno));
            break;
        }
        // Router received a msg.
        if(items[0].revents) {

            user = s_recv(data->router_socket);
            if(user == NULL) {
                LOG(LOG_LVL_ERRO, "Error getting user.");
                continue;
            }

            rc = zmq_msg_init(msg);
            if(rc != 0) {
                LOG(LOG_LVL_ERRO, "Error initializing msg");
                free(user);
                continue;
            }

            rc = zmq_msg_recv(msg, data->router_socket, 0);
            if(rc == -1) {
                LOG(LOG_LVL_ERRO, "Error receiving msg");
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
                LOG(LOG_LVL_ERRO, "Error initializing msg");
                continue;
            }
            rc = zmq_msg_init(out_msg);
            if(rc != 0) {
                LOG(LOG_LVL_ERRO, "Error initializing msg");
                zmq_close(msg);
                continue;
            }

            user = s_recv(data->inproc_socket);
            if(user == NULL) {
                LOG(LOG_LVL_ERRO, "Error getting user.");
                zmq_close(msg);
                zmq_close(out_msg);
                continue;
            }

            rc = zmq_msg_recv(msg, data->inproc_socket, 0);
            if(rc == -1) {
                LOG(LOG_LVL_ERRO, "Error receiving msg");
                free(user);
                zmq_close(msg);
                zmq_close(out_msg);
                continue;
            }

            rc = zmq_msg_copy(out_msg, msg);
            zmq_msg_close(msg);
            if(rc != 0) {
                LOG(LOG_LVL_ERRO, "Error copying msg");
                free(user);
                zmq_msg_close(out_msg);
                continue;
            }

            rc = s_sendmore(data->router_socket, user);
            free(user);
            if(rc == -1) {
                LOG(LOG_LVL_ERRO, "Error sending msg router socket.");
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
    LOG(LOG_LVL_INFO, "Closing router_socket_handler thread");
    zmq_close(data->inproc_socket);
    zmq_close(data->close_thread_socket);
    zmq_close(data->router_socket);
    free(data);
    return NULL;
}


int dtc_generate_key_shares(dtc_ctx_t *ctx, const char *key_id, size_t bit_size,
                            uint16_t threshold, uint16_t cant_nodes, bytes_t * public_exponent,
                            key_metainfo_t **info)
{
    key_share_t **key_shares = NULL;
    int ret;

    key_shares = tc_generate_keys(info, bit_size, threshold, cant_nodes, public_exponent);
    if(!key_shares)
        return DTC_ERR_INTERN;

    ret = store_key_shares_nodes(ctx, key_id, cant_nodes, info,
                                 key_shares);
    tc_clear_key_shares(key_shares, *info);
    if(ret != DTC_ERR_NONE) {
        dtc_delete_key_shares(ctx, key_id);
        tc_clear_key_metainfo(*info);
    }

    return ret;

}

static int store_key_shares_nodes(dtc_ctx_t *ctx, const char *key_id,
                                  uint16_t nodes_cant,
                                  key_metainfo_t **key_metainfo,
                                  key_share_t **key_shares)
{
    struct op_req pub_op;
    struct store_key_pub store_key_pub;
    struct handle_store_key_data store_key_data;
    union command_args *args = (union command_args *) &store_key_pub;
    int ret, i, return_on_timeout;
    void *remaining_key;
    unsigned prev, timeout_secs, timeout_usecs, retries = 2;
    uint16_t val;
    Buffer_t *keys;

    pub_op.version = 1;
    pub_op.op = OP_STORE_KEY_PUB;
    store_key_pub.instance_id = ctx->instance_id;
    store_key_pub.key_id = key_id;
    pub_op.args = args;

    divide_timeout(ctx->timeout, retries, &timeout_secs, &timeout_usecs);

    keys = newBuffer(nodes_cant);
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

    for(i = 0; i < nodes_cant; i++)
        put(keys, (void *)key_shares[i]);

    do{
        ret = send_pub_op(ctx, &pub_op);
        if(ret != DTC_ERR_NONE) {
            ht_get_and_delete_element(ctx->expected_msgs[OP_STORE_KEY_REQ],
                                      key_id, NULL);
            while(get_nowait(keys, (void **)&remaining_key) == 0)
                ;
            free_buffer(keys);
            uht_free(store_key_data.users_delivered);
            return ret;
        }

        return_on_timeout = wait_until_empty(keys, timeout_secs,
                                             timeout_usecs) == 0;
        if(!return_on_timeout)
            break;
    }while(retries--);


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

    if(ret != DTC_ERR_NONE || return_on_timeout) {
        uht_free(store_key_data.users_delivered);
        if(return_on_timeout)
            return DTC_ERR_TIMED_OUT;
        return ret;
    }

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

    send_pub_op(ctx, &pub_op);
}

int dtc_sign(dtc_ctx_t *ctx, const key_metainfo_t *key_metainfo,
             const char *key_id, bytes_t *message, bytes_t **out)
{
    struct op_req pub_op;
    struct sign_pub sign_pub;
    int ret, return_on_timeout, j, i = 0;
    char signing_id[37];
    int threshold = tc_key_meta_info_k(key_metainfo);
    int nodes_cant = tc_key_meta_info_l(key_metainfo);
    struct handle_sign_key_data sign_key_data;
    unsigned timeout_secs, timeout_usecs, retries = 2;
    signature_share_t *signature;
    Buffer_t *signatures_buffer;
    signature_share_t *signatures[nodes_cant];

    divide_timeout(ctx->timeout, retries, &timeout_secs, &timeout_usecs);

    get_uuid_as_char(signing_id);

    pub_op.args = (union command_args *) &sign_pub;
    pub_op.version = 1;
    pub_op.op = OP_SIGN_PUB;

    sign_pub.signing_id = signing_id;
    sign_pub.key_id = key_id;
    sign_pub.message = (uint8_t *)message->data;
    sign_pub.msg_len = message->data_len;

    signatures_buffer = newBuffer(nodes_cant);

    sign_key_data.signatures = signatures_buffer;
    sign_key_data.prepared_doc = message;
    sign_key_data.key_metainfo = key_metainfo;
    sign_key_data.user_already_signed = uht_init_hashtable();

    ret = ht_add_element(ctx->expected_msgs[OP_SIGN_REQ], signing_id,
                         (void *)&sign_key_data);
    if(ret == 0) {
        free_buffer(signatures_buffer);
        return DTC_ERR_INTERN;
    }

    do{
        ret = send_pub_op(ctx, &pub_op);
        if(ret != DTC_ERR_NONE) {
            LOG(LOG_LVL_CRIT, "Send pub msg error");
            free_buffer(signatures_buffer);
            uht_free(sign_key_data.user_already_signed);
            return ret;
        }

        return_on_timeout = wait_n_elements(signatures_buffer,
                threshold, timeout_secs, timeout_usecs) == 0;
        if(!return_on_timeout)
            break;
    } while(retries--);

    ret = ht_get_and_delete_element(ctx->expected_msgs[OP_SIGN_REQ], signing_id,
                                    NULL);
    assert(ret == 1);

    while(get_nowait(signatures_buffer, (void **)&signature) == 0)
        signatures[i++] = (signature_share_t *)signature;

    if(!return_on_timeout) {
        *out = tc_join_signatures((const signature_share_t **)signatures,
                                  message, key_metainfo);
    }

    for(j = 0; j < i; j++)
        tc_clear_signature_share(signatures[j]);

    free_buffer(signatures_buffer);
    uht_free(sign_key_data.user_already_signed);
    if(return_on_timeout)
        return DTC_ERR_TIMED_OUT;

    return DTC_ERR_NONE;
}

int dtc_destroy(dtc_ctx_t *ctx)
{
    int i;
    if(!ctx)
        return DTC_ERR_NONE;
    zmq_close(ctx->pub_socket);

    close_router_thread(ctx->zmq_ctx);
    // This will trigger a ETERM at monitoring thread and close its sockets
    // It is important the monitor sockets are closed after the monitored
    // sockets, otherwise it could lead to a deadlock when closing.
    zmq_ctx_shutdown(ctx->zmq_ctx);

    pthread_join(ctx->router_socket_thr_pid, NULL);
    pthread_join(ctx->monitoring_thr_pid, NULL);

    zmq_ctx_term(ctx->zmq_ctx);
    for(i = 0; i < OP_MAX; i++)
        ht_free(ctx->expected_msgs[i]);


    free((void *)ctx->instance_id);
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

static int send_pub_op(dtc_ctx_t *ctx, struct op_req *pub_op)
{
    size_t msg_size = 0;
    char *msg_data = NULL;
    int ret;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;

    msg_size = serialize_op_req(pub_op, &msg_data);
    if(!msg_size) {
        LOG(LOG_LVL_CRIT, "Serialize error");
        return DTC_ERR_SERIALIZATION;
    }

    ret = zmq_msg_init_data(msg, msg_data, msg_size, free_wrapper, free);
    if(ret) {
        LOG(LOG_LVL_CRIT, "zmq_msg_init_data: %s", zmq_strerror(errno));
        free(msg_data);
        return DTC_ERR_INTERN;
    }

    pthread_mutex_lock(&ctx->pub_socket_mutex);
    ret = zmq_msg_send(msg, ctx->pub_socket, 0);
    pthread_mutex_unlock(&ctx->pub_socket_mutex);
    if(ret == 1) {
        LOG(LOG_LVL_CRIT, "Error sending the msg: %s", zmq_strerror(errno));
        zmq_msg_close(msg);
        return DTC_ERR_COMMUNICATION;
    }

    return DTC_ERR_NONE;
}

static int create_connect_sockets(const struct dtc_configuration *conf,
                                  struct dtc_ctx *ctx)
{
    void *pub_socket, *router_socket;
    void *monitors[2];
    struct monitoring_thread_data *mon_thread_data;
    int ret_val = 0;
    int i = 0;
    char *protocol = "tcp";
    const int BUFF_SIZE = 200;
    // This is the max time, in milisecs, between the socket is asked to close
    // and it does really close, during this time it try to send all the
    // messages queued.
    const int linger = 1500;
    char buff[BUFF_SIZE];
    int ret = DTC_ERR_NONE;

    void *zmq_ctx = zmq_ctx_new();
    if(!zmq_ctx) {
        LOG(LOG_LVL_CRIT, "Context initialization error.");
        return DTC_ERR_ZMQ_ERROR;
    }

    pub_socket = zmq_socket(zmq_ctx, ZMQ_PUB);
    monitors[0] = zmq_socket(zmq_ctx, ZMQ_PAIR);
    router_socket = zmq_socket(zmq_ctx, ZMQ_ROUTER);
    monitors[1] = zmq_socket(zmq_ctx, ZMQ_PAIR);
    if(!pub_socket || !monitors[0] || !router_socket || !monitors[1]) {
        LOG(LOG_LVL_CRIT, "Unable to create sockets %s.",
                  zmq_strerror(errno));
        return DTC_ERR_ZMQ_ERROR;
    }

    ret = zmq_socket_monitor(pub_socket, ZMQ_MONITOR_PUB_SOCKET,
                             ZMQ_EVENT_ALL);
    ret += zmq_socket_monitor(router_socket, ZMQ_MONITOR_ROUTER_SOCKET,
                              ZMQ_EVENT_ALL);
    ret += zmq_setsockopt(pub_socket, ZMQ_LINGER, &linger, sizeof(int));
    ret += zmq_setsockopt(router_socket, ZMQ_LINGER, &linger, sizeof(int));
    if(ret != 0) {
        ret = DTC_ERR_ZMQ_ERROR;
        goto err_exit;
    }

    ret = zmq_connect(monitors[0], ZMQ_MONITOR_PUB_SOCKET);
    ret += zmq_connect(monitors[1], ZMQ_MONITOR_ROUTER_SOCKET);
    if(ret != 0) {
        LOG(LOG_LVL_CRIT, "Error connecting monitors sockets:%s",
                  zmq_strerror(errno));
        ret = DTC_ERR_ZMQ_ERROR;
        goto err_exit;
    }

    ret = set_client_socket_security(pub_socket, conf->private_key,
                                     conf->public_key);
    if(ret)
        goto err_exit;

    ret = set_client_socket_security(router_socket, conf->private_key,
                                     conf->public_key);
    if(ret)
        goto err_exit;
    ret_val = zmq_setsockopt(router_socket, ZMQ_IDENTITY, ctx->instance_id,
                             strlen(ctx->instance_id));
    if(ret_val != 0) {
        ret = DTC_ERR_ZMQ_CURVE;
        goto err_exit;
    }

    for(i = 0; i < conf->nodes_cant; i++) {
    //for(i = conf->nodes_cant -1; i >= 0; i--) {
        ret_val = zmq_setsockopt(pub_socket, ZMQ_CURVE_SERVERKEY,
                                 conf->nodes[i].public_key,
                                 strlen(conf->nodes[i].public_key));
        if(ret_val) {
            LOG(LOG_LVL_CRIT,
                      "PUB socket: Error setting node %d public key: %s.", i,
                      strerror(errno));
            return DTC_ERR_ZMQ_CURVE;
        }

        ret_val = zmq_setsockopt(router_socket, ZMQ_CURVE_SERVERKEY,
                                 conf->nodes[i].public_key,
                                 strlen(conf->nodes[i].public_key));
        if(ret_val) {
            LOG(LOG_LVL_CRIT,
                      "ROUTER socket: Error setting node %d public key: %s.", i,
                      strerror(errno));
            return DTC_ERR_ZMQ_CURVE;
        }

        ret_val = snprintf(&buff[0], BUFF_SIZE, "%s://%s:%" PRIu16,
                           protocol, conf->nodes[i].ip,
                           conf->nodes[i].sub_port);
        if(ret_val >= BUFF_SIZE) {
            LOG(LOG_LVL_CRIT, "BUFF_SIZE %d is not enough to store %d",
                      BUFF_SIZE, ret_val);
            ret = DTC_ERR_INTERN;
            goto err_exit;
        }

        ret_val = zmq_connect(pub_socket, &buff[0]);
        if(ret_val) {
            LOG(LOG_LVL_CRIT, "Error connecting pub_socket to %s.", &buff[0]);
            ret = DTC_ERR_CONNECTION;
            goto err_exit;
        }
        LOG(LOG_LVL_NOTI, "PUB socket connected to %s", &buff[0]);

        ret_val = snprintf(&buff[0], BUFF_SIZE, "%s://%s:%" PRIu16,
                           protocol, conf->nodes[i].ip,
                           conf->nodes[i].dealer_port);
        if(ret_val >= BUFF_SIZE) {
            LOG(LOG_LVL_CRIT, "BUFF_SIZE %d is not enough to store %d",
                      BUFF_SIZE, ret_val);
            ret = DTC_ERR_INTERN;
            goto err_exit;
        }

        ret_val = zmq_connect(router_socket, &buff[0]);
        if(ret_val) {
            LOG(LOG_LVL_CRIT, "Error connecting router_socket to %s.",
                      &buff[0]);
            ret = DTC_ERR_CONNECTION;
            goto err_exit;
        }
        LOG(LOG_LVL_NOTI, "ROUTER socket connected to %s", &buff[0]);
    }

    ret = wait_n_connections(monitors, 2, conf->nodes_cant,
                             conf->timeout * 1000);
    if(ret != DTC_ERR_NONE)
        goto err_exit;



    mon_thread_data = (struct monitoring_thread_data *)malloc(
            sizeof(struct monitoring_thread_data));
    mon_thread_data->monitors = malloc(sizeof(void *) * 2);
    mon_thread_data->monitors_names = malloc(sizeof(char *) * 2);
    if(mon_thread_data == NULL || mon_thread_data->monitors == NULL
       || mon_thread_data->monitors_names == NULL) {
        LOG(LOG_LVL_CRIT, "Not enough memory for monitoring_thread_data");
        ret = DTC_ERR_NOMEM;
        goto err_exit;
    }
    mon_thread_data->monitors[0] = monitors[0];
    mon_thread_data->monitors[1] = monitors[1];
    mon_thread_data->monitors_names[0] = "PUB Socket";;
    mon_thread_data->monitors_names[1] = "ROUTER Socket";
    mon_thread_data->monitors_cant = 2;

    ret = pthread_create(&ctx->monitoring_thr_pid, NULL, monitoring_thread,
                         (void *)mon_thread_data);
    if(ret != 0) {
        LOG(LOG_LVL_CRIT, "Failed creating monitoring pthread.");
        ret = DTC_ERR_INTERN;
        goto err_exit;
    }

    ctx->zmq_ctx = zmq_ctx;
    ctx->pub_socket = pub_socket;
    ctx->router_socket = router_socket;

    return ret;

err_exit:
    zmq_close(pub_socket);
    zmq_close(router_socket);
    zmq_close(monitors[0]);
    zmq_close(monitors[1]);
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
        LOG(LOG_LVL_CRIT, "Error setting the client's public key: %s.",
                  strerror(errno));
        return DTC_ERR_ZMQ_CURVE;
    }

    rc = zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY, client_secret_key,
                        strlen(client_secret_key));
    if(rc) {
        LOG(LOG_LVL_CRIT, "Error setting the client's secret key: %s.",
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
static int read_configuration_file(const char *conf_file_path,
                                   struct dtc_configuration *conf)
{
    config_t cfg;
    config_setting_t *root, *master, *nodes, *element;
    int nodes_cant = 0, rc;
    unsigned int i = 0;
    int ret = DTC_ERR_CONFIG_FILE;

    config_init(&cfg);

    if(!config_read_file(&cfg, conf_file_path)) {
        LOG(LOG_LVL_CRIT, "%s:%d - %s\n", config_error_file(&cfg),
            config_error_line(&cfg), config_error_text(&cfg));
        goto err_exit;
    }

    root = config_root_setting(&cfg);
    master = config_setting_get_member(root, "master");
    if(!master){
        LOG(LOG_LVL_CRIT, "master was not found in the conf file %s",
            conf_file_path);
        goto err_exit;
    }

    nodes = config_setting_get_member(master, "nodes");
    if(!nodes) {
        LOG(LOG_LVL_CRIT, "nodes not specified in master configuration");
        goto err_exit;
    }

    nodes_cant = config_setting_length(nodes);
    if(nodes_cant == 0) {
        LOG(LOG_LVL_CRIT, "0 nodes specified for master");
        goto err_exit;
    }

    conf->nodes_cant = nodes_cant;
    conf->nodes =
            (struct node_info *) malloc(sizeof(struct node_info) * nodes_cant);
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

    ret = lookup_string_conf_element(master, "instance_id", &conf->instance_id);
    if(ret != DTC_ERR_NONE)
        goto err_exit;

    rc = lookup_uint16_conf_element(master, "timeout", &conf->timeout);
    if(rc != DTC_ERR_NONE) {
        LOG(LOG_LVL_NOTI,
                  "Error reading timeout from config, using default:%" PRIu16,
                  DEFAULT_TIMEOUT);
        conf->timeout = DEFAULT_TIMEOUT;
    }

    for(i = 0; i < nodes_cant; i++) {
        memset((void *)&conf->nodes[i], 0, sizeof(struct node_info));
        element = config_setting_get_elem(nodes, i);
        if(element == NULL) {
            LOG(LOG_LVL_CRIT, "Error getting element %u from nodes.", i);
            goto err_exit;
        }

        ret = lookup_string_conf_element(element, "ip", (const char **)&conf->nodes[i].ip);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

        ret = lookup_string_conf_element(element, "public_key",
                                         (const char **)&conf->nodes[i].public_key);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

        ret = lookup_uint16_conf_element(element, "sub_port",
                                         (uint16_t *)&conf->nodes[i].sub_port);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

        ret = lookup_uint16_conf_element(element, "dealer_port",
                                         (uint16_t *)&conf->nodes[i].dealer_port);
        if(ret != DTC_ERR_NONE)
            goto err_exit;

    }

    config_destroy(&cfg);

    return DTC_ERR_NONE;

err_exit:
    free_nodes(nodes_cant, (struct node_info *)conf->nodes);
    nodes_cant = 0;
    config_destroy(&cfg);
    return ret;
}
