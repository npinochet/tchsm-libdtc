#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <libconfig.h>
#include <zmq.h>

#include <dtc.h>

#include "database.h"
#include "logger.h"
#include "messages.h"
#include "utilities.h"


struct master_info {
    // master_id.
    const char *id;

    // master public key.
    const char *public_key;
};

struct configuration {

    char *configuration_file;

    // Interface to open the connection.
    const char *interface;

    // Path to the file with the database.
    const char *database;

    // Port number to bind the SUB socket in.
    uint16_t sub_port;

    // Port number to bind the ROUTER socket in.
    uint16_t router_port;

    // Behaviour on multiple connections.
    multiple_connections_t  multiple_connections;

    size_t cant_masters;

    struct master_info *masters;

    const char *public_key;

    const char *private_key;
};

struct worker_data {
    void *ctx;
    pthread_t *pids;
    uint16_t num_workers;
    const char *incoming_inproc_address;
    const char *outgoing_inproc_address;
    const char *database_path;
    // Behaviour on multiple connections.
    multiple_connections_t  multiple_connections;
};

struct communication_objects {
    void *ctx;
    void *sub_socket;
    void *router_socket;
    void *zap_thread;
    struct worker_data *workers;

    // Outgoing msgs
    char *outgoing_inproc_address;
    void *outgoing_socket;

    // Incoming msgs
    char *incoming_inproc_address;
    void *incoming_socket;
};

struct zap_handler_data {
    // Inproc socket.
    void *socket;

    // Path to the database file.
    const char *database;

    // Behaviour on multiple connections.
    multiple_connections_t  multiple_connections;
};

// ptr to the ctx to be used by the signal handler.
static int CLEANUP_PIPE;

const int LINGER_PERIOD = 100;

/* Utils */

/* Safe conversion from str to uint16_t */
int str_to_uint16(const char *str, uint16_t *res)
{
    errno = 0;
    unsigned long int result = strtoul(str, NULL, 10);
    if (errno == ERANGE || result > UINT16_MAX)
        return 1;
    *res = (uint16_t)result;
    return 0;
}

void lookup_multiple_connections(const config_setting_t *setting,
                                 multiple_connections_t *out)
{
    const char *val;
    int rc;
    multiple_connections_t ret = SAME_IP; // Default
    rc = lookup_string_conf_element(setting, "multiple_connections", &val);
    if(rc != DTC_ERR_NONE) {
        *out = ret;
        return;
    }

    if(strcmp("SAME_IP", val) == 0)
        ret = SAME_IP;
    else if(strcmp("ONE_CONNECTION", val) == 0)
        ret = ONE_CONNECTION;
    else
        LOG(LOG_LVL_WARN, "Not a valid multiple_connections configuration %s",
                val);
    free((void *)val);
    *out = ret;
}

/* Return a human readable version of the configuration */
static char* configuration_to_string(const struct configuration *conf)
{
    /* Be aware, this memory is shared among the aplication, this function
     * should be called just once or the memory of the previous calls might get
     * corrupted.
     */
    static char buff[200];

    snprintf(buff, sizeof(buff),
             "\nInterface:\t%s\nSUB port:\t%" PRIu16 "\n"
             "Router port:\t%" PRIu16,
             conf->interface, conf->sub_port, conf->router_port);
    return &buff[0];
}

// Just declarations, see definitions for documentation.
static int read_configuration(int argc, char *argv[], struct configuration *conf);
static struct communication_objects *init_node(const struct configuration *conf);
static struct communication_objects *create_and_bind_sockets(
        const struct configuration *conf);
static int node_loop(struct communication_objects *communication_objs,
                     const char * database_path, int close_fds,
                     multiple_connections_t mult_conn);
static int set_server_socket_security(void *socket,
                                      const char *server_secret_key);
static void zap_handler (void *handler);

/**
 * Print one line of usage to stdout.
 *
 * @param exit_code: if exit_code >= 0, exit with exit_code, otherwise do not
 *      exit.
 **/
static void print_usage(int exit_code)
{
    fprintf(stdout, "usage: node [-c, --config=<configuration_file>]\n");
    if(exit_code >= 0)
        exit(exit_code);
}

/* Update masters in the Database to keep it sync with the config file */
static void update_database(struct configuration *conf)
{
    unsigned i;
    database_t *db_conn = db_init_connection(conf->database, 1,
                                             conf->multiple_connections);
    EXIT_ON_FALSE(db_conn, "Error trying to connect to the database.");

    for(i = 0; i < conf->cant_masters; i++) {
        if(db_add_new_instance(db_conn, conf->masters[i].id,
                             conf->masters[i].public_key))
            LOG_EXIT("Error adding new instance.");
    }

    EXIT_ON_FALSE(db_update_instances(db_conn) == 0, "Update instances failed.");
    db_close_and_free_connection(db_conn);
}

int main(int argc, char **argv)
{
    int ret_val = 0;
    unsigned i;

    // Default configuration.
    static struct configuration configuration =
            {.configuration_file = "./libdtc.conf"};
#ifdef NDEBUG
    OPEN_LOG();
#else
    OPEN_LOG(NULL, LOG_CONS | LOG_PERROR, LOG_LOCAL0);
#endif

    ret_val = read_configuration(argc, argv, &configuration);
    if(ret_val)
        return 1;

    LOG(LOG_LVL_INFO, "Logger configuration:%s",
        configuration_to_string(&configuration));

    update_database(&configuration);

    int fds[2];
    if(pipe(fds))
        PERROR_RET(1, "pipe CLEANUP_PIPE");
    if(fcntl(fds[0], F_SETFL, fcntl(fds[0], F_GETFL) | O_NONBLOCK) < 0)
        PERROR_RET(1, "fcntl  F_SETFL");
    CLEANUP_PIPE = fds[1];


    struct communication_objects *communication_objs =
            init_node(&configuration);
    if(!communication_objs)
        return 1;

    LOG(LOG_LVL_NOTI, "Node started: %s", argv[0]);

    ret_val = node_loop(communication_objs, configuration.database, fds[0],
                        configuration.multiple_connections);

    zmq_ctx_destroy(communication_objs->ctx);
    zmq_threadclose(communication_objs->zap_thread);
    for(i = 0; i < communication_objs->workers->num_workers; i++) {
        pthread_join(communication_objs->workers->pids[i], NULL);
    }
    free(communication_objs->workers->pids);
    free(communication_objs->workers);
    free(communication_objs);


    free((void *)configuration.public_key);
    free((void *)configuration.private_key);
    free((void *)configuration.interface);
    free((void *)configuration.database);
    for(i = 0; i < configuration.cant_masters; i++) {
        free((void *)configuration.masters[i].id);
        free((void *)configuration.masters[i].public_key);
    }
    free((void *)configuration.masters);

    return ret_val;
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
    config_setting_t *root, *masters, *node, *element;
    int cant_masters = 0;
    unsigned int i = 0;
    int ret = DTC_ERR_CONFIG_FILE;

    config_init(&cfg);

    EXIT_ON_FALSE(CONFIG_TRUE == config_read_file(&cfg,
                                                  conf->configuration_file),
                  "Error opening config file %s, line %d - %s\n",
                  config_error_file(&cfg) == NULL ? conf->configuration_file :
                                                    config_error_file(&cfg),
                  config_error_line(&cfg), config_error_text(&cfg));

    root = config_root_setting(&cfg);
    node = config_setting_get_member(root, "node");
    EXIT_ON_FALSE(node, "node was not found in the conf file %s",
                  conf->configuration_file);

    masters = config_setting_get_member(node, "masters");
    EXIT_ON_FALSE(masters, "masters not specified in node configuration");

    cant_masters = config_setting_length(masters);
    EXIT_ON_FALSE(cant_masters, "0 masters specified for master");

    conf->cant_masters = cant_masters;
    conf->masters = (struct master_info *) malloc(
            sizeof(struct master_info) * cant_masters);
    EXIT_ON_FALSE(conf->masters, "Not memory to store the masters.");

    ret = lookup_string_conf_element(node, "database", &conf->database);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Database file not specified.");

    ret = lookup_string_conf_element(node, "private_key", &conf->private_key);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Unable to retrieve private key.");

    ret = lookup_string_conf_element(node, "public_key", &conf->public_key);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Unable to retrieve public key.");

    ret = lookup_string_conf_element(node, "interface", &conf->interface);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Unable to retrieve interface.");

    ret = lookup_uint16_conf_element(node, "router_port", &conf->router_port);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Unable to retrieve router_port.");

    ret = lookup_uint16_conf_element(node, "sub_port", &conf->sub_port);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Unable to retrieve sub_port.");

    lookup_multiple_connections(node, &conf->multiple_connections);

    for(i = 0; i < cant_masters; i++) {
        element = config_setting_get_elem(masters, i);
        EXIT_ON_FALSE(element, "Error getting element %u from masters", i);

        ret = lookup_string_conf_element(element, "public_key",
                                         &conf->masters[i].public_key);
        EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Exit.");

        ret = lookup_string_conf_element(element, "id", &conf->masters[i].id);
        EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Exit.");
    }

    config_destroy(&cfg);
    return DTC_ERR_NONE;
}


/**
 * Read the command line configuration.
 *
 * Args:
 *  argc: main's argc.
 *  argv: main's argv.
 *
 * Returns:
 *  1 on unrecoverable error, 0 otherwise.
 */
static int read_configuration(int argc, char *argv[],
                              struct configuration *conf)
{
    int option_index = 0;
    char c;
    static int help = 0;
    static struct option long_options[] = {
        {"help", no_argument, &help, 1},
        {"config", required_argument, 0, 'c'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}};

    while((c = getopt_long(argc, argv, ":c:vh", long_options,
                           &option_index)) != -1) {
        switch(c) {
        case 'c':
            conf->configuration_file = optarg;
            break;
        case 'v':
            LOG(LOG_LVL_CRIT, "Not implemented yet :(");
            break;
        case 'h':
            print_usage(0);
            break;
        case ':':
            LOG(LOG_LVL_CRIT, "Missing parameter for %c (%s).", optopt,
                argv[optind -1 ]);
            return 1;
        case '?':
            LOG(LOG_LVL_CRIT, "Invalid option found. (%s).", argv[optind - 1]);
            print_usage(EXIT_FAILURE);
            break;
        case 1:
            break;
        default:
            break;
        }
    }
    if(help)
        print_usage(0);
    read_configuration_file(conf);

    return 0;
}

// Serialize and send an op to router, will write the instance id as first frame
// of the message, that's used to select the destination in a router socket.
static int send_op(const char *identity, const struct op_req *op, void *socket)
{
    size_t msg_size = 0;
    char *msg_data = NULL;
    int ret;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;

    msg_size = serialize_op_req(op, &msg_data);
    if(!msg_size) {
        LOG(LOG_LVL_CRIT, "Serialize error at send_op");
        return DTC_ERR_SERIALIZATION;
    }

    ret = zmq_msg_init_data(msg, msg_data, msg_size, free_wrapper, free);
    if(ret) {
        LOG(LOG_LVL_CRIT, "zmq_msg_init_data: %s", zmq_strerror(errno));
        free(msg_data);
        return DTC_ERR_INTERN;
    }

    ret = s_sendmore(socket, identity);
    if(ret == 0) {
        zmq_msg_close(msg);
        return DTC_ERR_COMMUNICATION;
    }

    ret = zmq_msg_send(msg, socket, 0);
    if(ret == 0) {
        zmq_msg_close(msg);
        return DTC_ERR_COMMUNICATION;
    }
    LOG(LOG_LVL_DEBG, "Sending %d to %s\n", op->op, identity);
    return DTC_ERR_NONE;
}

/**
 * Store the key received in the database.
 *
 * @param db_conn Active connection with the database.
 * @param instance_id Id of the instance the key is asociated with.
 * @param res_op Communication struct with the key.
 */
void store_key(database_t *db_conn, const char *instance_id,
               struct store_key_res *res_op)
{
    int rc;
    char *key_metainfo = tc_serialize_key_metainfo(res_op->meta_info);
    char *key_share = tc_serialize_key_share(res_op->key_share);
    rc = db_store_key(
            db_conn, instance_id, res_op->key_id, key_metainfo, key_share);
    free(key_metainfo);
    free(key_share);
    if(rc == DTC_ERR_NONE)
        LOG(LOG_LVL_INFO, "Successfully stored key %s from instance %s.",
            res_op->key_id, instance_id);
    else
        LOG(LOG_LVL_NOTI, "Error adding key %s from instance %s.", res_op->key_id,
            instance_id);
    return;
}

//TODO do we need to handle only request after store_key_pub was called?
void handle_store_key_res(database_t *db_conn, void *outgoing_socket,
                          struct op_req *res_op, const char *auth_user)
{
    char *instance_id;

    if(DTC_ERR_NONE != db_get_instance_id_from_router_token(db_conn, auth_user,
                                                            &instance_id)) {
        LOG(LOG_LVL_ERRO, "Error adding key");
        return;
    }
    store_key(db_conn, instance_id, &res_op->args->store_key_res);
    free(instance_id);
}

void handle_delete_key_share_pub(database_t *db_conn, void *router_socket,
                                 struct op_req *pub_op, const char *auth_user)
{
    const char *key_id, *connection_id;
    struct op_req req_op;
    struct delete_key_share_req delete_key_share;
    char *identity, *instance_id;

    if(pub_op->version != 1) {
        LOG(LOG_LVL_ERRO, "Version %" PRIu16 " not supported", pub_op->version);
        return;
    }


    key_id = pub_op->args->delete_key_share_pub.key_id;
    connection_id = pub_op->args->delete_key_share_pub.connection_id;

    if(DTC_ERR_NONE != db_get_identity_and_instance_from_pub_token(
            db_conn, auth_user, connection_id, &identity, &instance_id)) {
        LOG(LOG_LVL_ERRO,
            "Error getting identity at handle_delete_key_share_pub");
        return;

    }

    delete_key_share.key_id = key_id;
    delete_key_share.deleted = db_delete_key(db_conn, instance_id, key_id);
    if(delete_key_share.deleted == DTC_ERR_NONE)
        LOG(LOG_LVL_INFO, "Successfully deleted key %s from instance %s",
            key_id, instance_id);

    req_op.version = 1;
    req_op.op = OP_DELETE_KEY_SHARE_REQ;
    req_op.args = (union command_args *)&delete_key_share;

    send_op(identity, &req_op, router_socket);
    free(instance_id);
    free(identity);
    return;
}

const signature_share_t *sign(database_t *db_conn, const char *instance_id,
                              const char *key_id, const bytes_t *msg_bytes)
{
    signature_share_t *signature;
    char *key_share;
    char *key_metainfo;
    key_share_t *k_share;
    key_metainfo_t *k_metainfo;
    int ret;

    ret = db_get_key(db_conn, instance_id, key_id, &key_share, &key_metainfo);
    if(ret != DTC_ERR_NONE) {
        LOG(LOG_LVL_NOTI, "Error (%d) getting keys for instance %s and key %s.",
            ret, instance_id, key_id);
        return NULL;
    }

    k_metainfo = tc_deserialize_key_metainfo(key_metainfo);
    k_share = tc_deserialize_key_share(key_share);

    signature = tc_node_sign(k_share, msg_bytes, k_metainfo);
    ret = tc_verify_signature(signature, msg_bytes, k_metainfo);

    tc_clear_key_share(k_share);
    tc_clear_key_metainfo(k_metainfo);
    free(key_metainfo);
    free(key_share);

    if(ret != 1) {
        LOG(LOG_LVL_ERRO, "Error verifying the signature.");
        return NULL;
    }

    return signature;
}

void handle_sign_pub(database_t *db_conn, void *router_socket,
                     struct op_req *pub_op, const char *auth_user)
{
    char *identity, *instance_id;
    const char *key_id, *connection_id, *signing_id;
    const uint8_t *message;
    struct op_req req;
    struct sign_req sign_req;
    size_t msg_len;
    const signature_share_t *signature;
    bytes_t *msg_bytes;

    if(pub_op->version != 1) {
        LOG(LOG_LVL_ERRO, "version %" PRIu16 " not supported.",
                pub_op->version);
        return;
    }

    signing_id = pub_op->args->sign_pub.signing_id;
    key_id = pub_op->args->sign_pub.key_id;
    message = pub_op->args->sign_pub.message;
    msg_len = pub_op->args->sign_pub.msg_len;
    connection_id = pub_op->args->sign_pub.connection_id;

    if(DTC_ERR_NONE != db_get_identity_and_instance_from_pub_token(
            db_conn, auth_user, connection_id, &identity, &instance_id)) {
        LOG(LOG_LVL_ERRO, "Error getting identity at handle_sign_pub");
        return;
    }

    msg_bytes = tc_init_bytes((void *)message, msg_len);

    signature = sign(db_conn, instance_id, key_id, msg_bytes);
    free(msg_bytes);
    free(instance_id);

    //TODO send status code.
    if(!signature) {
        free(identity);
        return;
    }

    req.op = OP_SIGN_REQ;
    req.version = 1;
    req.args = (union command_args *)&sign_req;
    sign_req.status_code = 0;
    sign_req.signing_id = signing_id;
    sign_req.signature = signature;

    send_op(identity, &req, router_socket);
    tc_clear_signature_share((signature_share_t *)signature);
    free(identity);
}

void handle_store_key_pub(database_t *db_conn, void *outgoing_socket,
                          struct op_req *pub_op, const char *auth_user)
{
    const char *connection_id;
    char *instance_id, *identity;
    struct op_req req_op;
    struct store_key_req store_key_req;
    int ret;

    if(pub_op->version != 1) {
        LOG(LOG_LVL_ERRO, "version %" PRIu16 " not supported.", pub_op->version);
        return;
    }

    connection_id = pub_op->args->store_key_pub.connection_id;
    ret = db_get_identity_and_instance_from_pub_token(db_conn, auth_user,
                                                      connection_id,
                                                      &identity, &instance_id);
    if(ret != DTC_ERR_NONE) {
        LOG(LOG_LVL_CRIT,
            "Error getting instance_id from handle_store_key_pub");
        return;
    }

    store_key_req.key_id = pub_op->args->store_key_pub.key_id;

    req_op.version = 1;
    req_op.op = OP_STORE_KEY_REQ;
    req_op.args = (union command_args *)&store_key_req;

    store_key_req.key_id_accepted =
            db_is_key_id_available(db_conn, instance_id, store_key_req.key_id);

    ret = send_op(identity, &req_op, outgoing_socket);
    if(ret != DTC_ERR_NONE)
        LOG(LOG_LVL_CRIT, "Error replying from handle_store_key_pub: %s",
            dtc_get_error_msg(ret));
    free((void *)instance_id);
    free((void *)identity);
    return;
}

void classify_and_handle_operation(database_t *db_conn, void *outgoing_socket,
                                   struct op_req *op, const char *auth_user)
{
    unsigned i;
    #define TOTAL_SUPPORTED_OPS 4
    uint16_t supported_operations[TOTAL_SUPPORTED_OPS] = {OP_STORE_KEY_PUB,
                                                          OP_STORE_KEY_RES,
                                                          OP_SIGN_PUB,
                                                          OP_DELETE_KEY_SHARE_PUB};
    static void (*const op_handlers[TOTAL_SUPPORTED_OPS]) (
                                                    database_t *db_conn,
                                                    void *outgoing_socket,
                                                    struct op_req *op,
                                                    const char *auth_user) = {
            handle_store_key_pub,
            handle_store_key_res,
            handle_sign_pub,
            handle_delete_key_share_pub
    };

    for(i = 0; i < TOTAL_SUPPORTED_OPS; i++) {
        if(op->op == supported_operations[i])
            break;
    }
    if(i == TOTAL_SUPPORTED_OPS) {
        LOG(LOG_LVL_ERRO, "Operation %" PRIu32 " not supported.", op->op);
        return;
    }
    LOG(LOG_LVL_DEBG, "Got an op %u", supported_operations[i]);

    (op_handlers[i])(db_conn, outgoing_socket, op, auth_user);

    return;

}

static void *worker_thr(void *thread_data)
{
    int rc = 0;
    void *incoming_socket = NULL;
    void *outgoing_socket = NULL;
    char *auth_master_id;
    int close_thread = 0;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;
    struct op_req *op;
    database_t *db_conn;

    struct worker_data *thr_data = (struct worker_data *) thread_data;

    incoming_socket = zmq_socket(thr_data->ctx, ZMQ_PULL);
    outgoing_socket = zmq_socket(thr_data->ctx, ZMQ_PUSH);
    if(!incoming_socket || !outgoing_socket) {
        LOG_EXIT("Unable to create sockets");
    }
    if(zmq_setsockopt(incoming_socket, ZMQ_LINGER, &LINGER_PERIOD, sizeof(int)))
        LOG_EXIT("LINGER FAILED");
    if(zmq_setsockopt(outgoing_socket, ZMQ_LINGER, &LINGER_PERIOD, sizeof(int)))
        LOG_EXIT("LINGER FAILED");

    rc = zmq_connect(incoming_socket, thr_data->incoming_inproc_address);
    rc += zmq_connect(outgoing_socket, thr_data->outgoing_inproc_address);
    if(rc != 0) {
        LOG_EXIT("Unable to connect socket: %s", zmq_strerror(errno));
    }

    db_conn = db_init_connection(thr_data->database_path, 0,
                                 thr_data->multiple_connections);
    EXIT_ON_FALSE(db_conn, "Unable to init db connection at:%s",
                  thr_data->database_path);

    LOG(LOG_LVL_NOTI, "Worker thread ready!");

    while(!close_thread) {
        rc = zmq_msg_init(msg);
        if(rc != 0) {
            LOG(LOG_LVL_ERRO, "Unable to init msg: %s", zmq_strerror(errno));
            continue;
        }

        auth_master_id = s_recv(incoming_socket);
        if(auth_master_id == NULL) {
            if(errno == ETERM) {
                LOG(LOG_LVL_INFO, "Closing working thread");
                break;
            }
            LOG(LOG_LVL_ERRO, "User id is null: %s", zmq_strerror(errno));
            continue;
        }

        rc = zmq_msg_recv(msg, incoming_socket, 0);
        if(rc == -1){
            LOG(LOG_LVL_ERRO, "Receive message failed:%s", zmq_strerror(errno));
            free(auth_master_id);
            zmq_msg_close(msg);
            continue;
        }

        op = unserialize_op_req(zmq_msg_data(msg), rc);
        if(op == NULL) {
            LOG(LOG_LVL_ERRO, "Unable to unserialize the received msg.");
            zmq_msg_close(msg);
            free(auth_master_id);
            continue;
        }

        classify_and_handle_operation(db_conn, outgoing_socket, op,
                                      auth_master_id);
        delete_op_req(op);
        free(auth_master_id);
        rc = zmq_msg_close(msg);
        if(rc)
            LOG(LOG_LVL_ERRO, "Error closing the msg:%s", zmq_strerror(errno));
    }
    zmq_close(incoming_socket);
    zmq_close(outgoing_socket);
    db_close_and_free_connection(db_conn);
    return NULL;
}

static struct worker_data *create_workers(int num_workers,
                                          const char * database_path,
                                          multiple_connections_t mult_conn,
                                          void *zmq_ctx,
                                          const char *incoming_inproc_address,
                                          const char *outgoing_inproc_address)
{
    unsigned i;
    int ret;

    struct worker_data *worker_data =
        (struct worker_data *) malloc(sizeof(struct worker_data));
    worker_data->pids = malloc(num_workers * sizeof(pthread_t));
    worker_data->num_workers = num_workers;

    worker_data->incoming_inproc_address = incoming_inproc_address;
    worker_data->outgoing_inproc_address = outgoing_inproc_address;
    worker_data->database_path = database_path;
    worker_data->ctx = zmq_ctx;
    worker_data->multiple_connections = mult_conn;
    for(i = 0; i < num_workers; i++) {
        ret = pthread_create(&(worker_data->pids[i]), NULL, worker_thr,
                             worker_data);
        if(ret != 0) {
            LOG_EXIT("Failed creating a worker thread");
        }
    }
    return worker_data;
}

static void signal_handler(int sign)
{
    if(sign == SIGINT) {
        char *close_msg = "Got a SIGINT signal, going to exit.\n";
        LOG(LOG_LVL_INFO, "Closing the node");
        int rc = write(CLEANUP_PIPE, close_msg, strlen(close_msg) + 1);
        close(CLEANUP_PIPE);
        if(rc == -1) {
            PERROR_AND_EXIT_ON_FALSE(0, "Clean up failed", "write");
            exit(1);
        }
    }
    else {
        LOG_EXIT("Got unexpected signal");
    }
}

static void set_signals()
{
    sigset_t set;
    struct sigaction action;

    sigemptyset(&set);
    sigaddset(&set, SIGINT);

    memset(&action, '\0', sizeof(struct sigaction));
    action.sa_handler = signal_handler;
    action.sa_mask = set;
    action.sa_flags = SA_NODEFER;

    if(sigaction(SIGINT, &action, NULL))
        LOG_EXIT("Error, sigaction failed %s", strerror(errno));
}

static struct communication_objects *init_node(
        const struct configuration *configuration)
{
    int num_workers = 20;

    struct communication_objects *comm_objs;

    comm_objs = create_and_bind_sockets(configuration);


    comm_objs->workers = create_workers(num_workers,
                                        configuration->database,
                                        configuration->multiple_connections,
                                        comm_objs->ctx,
                                        comm_objs->incoming_inproc_address,
                                        comm_objs->outgoing_inproc_address);

    set_signals();
    return comm_objs;
}

static void *start_zap_security(void *zmq_ctx, const char *database,
                                multiple_connections_t mult_conn)
{
    int ret_value;
    struct zap_handler_data *zap_data =
        (struct zap_handler_data *) malloc(sizeof(struct zap_handler_data));
    EXIT_ON_FALSE(zap_data, "malloc failed for zap_handler_data.");

    zap_data->database = database;
    zap_data->socket = zmq_socket(zmq_ctx, ZMQ_REP);
    zap_data->multiple_connections = mult_conn;
    if(zmq_setsockopt(zap_data->socket, ZMQ_LINGER, &LINGER_PERIOD, sizeof(int)))
        LOG_EXIT("LINGER FAILED");
    EXIT_ON_FALSE(zap_data->socket, "ZAP_HANDLER socket error.");

    ret_value = zmq_bind(zap_data->socket, "inproc://zeromq.zap.01");
    EXIT_ON_FALSE(ret_value == 0, "ZAP_HANDLER bind error.");
    return zmq_threadstart(&zap_handler, zap_data);
}
/**
 * TODO
 **/
static struct communication_objects *create_and_bind_sockets(
        const struct configuration *conf)
{
    const size_t bind_buff_length = 200;
    char bind_buff[bind_buff_length];
    struct communication_objects *ret_val =
        (struct communication_objects *) malloc(
                sizeof(struct communication_objects));

    void *sub_socket = NULL, *router_socket = NULL;
    int ret_value = 0;
    int enabled = 1;
    ret_val->outgoing_inproc_address = "inproc://outgoing";
    ret_val->incoming_inproc_address = "inproc://incoming";

    ret_val->ctx = zmq_ctx_new();
    EXIT_ON_FALSE(ret_val->ctx, "Context initialization error.");

    ret_val->zap_thread = start_zap_security(ret_val->ctx, conf->database,
                                             conf->multiple_connections);

    // Create sockets.
    ret_val->incoming_socket = zmq_socket(ret_val->ctx, ZMQ_PUSH);
    ret_val->outgoing_socket = zmq_socket(ret_val->ctx, ZMQ_PULL);
    ret_val->sub_socket = zmq_socket(ret_val->ctx, ZMQ_SUB);
    ret_val->router_socket = zmq_socket(ret_val->ctx, ZMQ_ROUTER);
    sub_socket = ret_val->sub_socket;
    if(zmq_setsockopt(ret_val->incoming_socket, ZMQ_LINGER, &LINGER_PERIOD, sizeof(int)))
        LOG_EXIT("LINGER FAILED");
    if(zmq_setsockopt(ret_val->outgoing_socket, ZMQ_LINGER, &LINGER_PERIOD, sizeof(int)))
        LOG_EXIT("LINGER FAILED");
    if(zmq_setsockopt(ret_val->sub_socket, ZMQ_LINGER, &LINGER_PERIOD, sizeof(int)))
        LOG_EXIT("LINGER FAILED");
    if(zmq_setsockopt(ret_val->router_socket, ZMQ_LINGER, &LINGER_PERIOD, sizeof(int)))
        LOG_EXIT("LINGER FAILED");
    router_socket = ret_val->router_socket;

    if(!ret_val->incoming_socket || !ret_val->outgoing_socket ||
       !ret_val->sub_socket || !ret_val->router_socket) {
        LOG_EXIT("Unable to create socket: %s", zmq_strerror(errno));
    }

    // Bind inproc sockets
    ret_value = zmq_bind(ret_val->incoming_socket,
                         ret_val->incoming_inproc_address);
    EXIT_ON_FALSE(!ret_value, "Bind failed (%s) at: %s.", zmq_strerror(errno),
                  ret_val->incoming_inproc_address);

    ret_value = zmq_bind(ret_val->outgoing_socket,
                         ret_val->outgoing_inproc_address);
    EXIT_ON_FALSE(!ret_value, "Bind failed (%s) at: %s.", zmq_strerror(errno),
                  ret_val->outgoing_inproc_address);

    // Activate ZAP security for authentication.
    ret_value = zmq_setsockopt(sub_socket, ZMQ_ZAP_DOMAIN, "SUB_SOCKET", 10);
    PERROR_AND_EXIT_ON_FALSE(ret_value == 0, "zmq_setsockopt",
                             "ZMQ_ZAP_DOMAIN failed.");

    ret_value = zmq_setsockopt(router_socket, ZMQ_ZAP_DOMAIN, "ROUTER_SOCKET",
                               13);
    PERROR_AND_EXIT_ON_FALSE(ret_value == 0, "zmq_setsockopt",
                             "ZMQ_ZAP_DOMAIN failed for router socket.");

    // This cause that the router accept a new connection with a previously
    // used identity, disconnecting the old one.
    ret_value = zmq_setsockopt(router_socket, ZMQ_ROUTER_HANDOVER, &enabled,
                               sizeof(enabled));
    PERROR_AND_EXIT_ON_FALSE(ret_value == 0, "zmq_setsockopt",
                             "ZMQ_ROUTER_HANDOVER failed for router socket.");

    ret_value = zmq_setsockopt(router_socket, ZMQ_IDENTITY, conf->public_key,
                               strlen(conf->public_key));
    PERROR_AND_EXIT_ON_FALSE(ret_value == 0, "zmq_setsockopt",
                             "ZMQ_IDENTITY failed for router socket.");

    // Set curve security for encryption.
    if(set_server_socket_security(sub_socket, conf->private_key) ||
        set_server_socket_security(router_socket, conf->private_key))
        exit(1);

    //TODO(fmontoto) Dumping both bind addresses is the same code, refactor
    //into a function?
    ret_value = snprintf(&bind_buff[0], bind_buff_length, "tcp://%s:%d",
                         conf->interface, conf->sub_port);
    if(ret_value >= bind_buff_length){
        LOG(LOG_LVL_CRIT, "Bind buffer too small (%zu), required: %d.",
            bind_buff_length, ret_value);
        exit(1);
    }

    ret_value = zmq_bind(sub_socket, bind_buff);
    EXIT_ON_FALSE(!ret_value, "Bind failed at: %s.", bind_buff);

    ret_value = zmq_setsockopt(sub_socket, ZMQ_SUBSCRIBE, NULL, 0);
    EXIT_ON_FALSE(ret_value == 0, "ZMQ_SUBSCRIBE failed.");

    ret_value = snprintf(&bind_buff[0], bind_buff_length, "tcp://%s:%d",
                         conf->interface, conf->router_port);
    if(ret_value >= bind_buff_length){
        LOG(LOG_LVL_CRIT, "Bind buffer too small (%zu), required: %d.",
            bind_buff_length, ret_value);
        exit(1);
    }

    ret_value = zmq_bind(router_socket, bind_buff);
    EXIT_ON_FALSE(!ret_value, "Bind failed at: %s.", bind_buff);

    LOG(LOG_LVL_NOTI, "Both sockets bound, node ready to talk with the Master.");
    return ret_val;
}

/**
 * Activate security in the socket, must be called before the bind.
 *
 * Args:
 *  socket: Socket to activate the security into, should be already created and
 *      the security will be activated just in binds after this call.
 *  server_secret_key: Secret key of this server.
 *
 *  Returns:
 *   0 on success, a non zero value indicates that the socket is not secure.
 */
// TODO const the key
static int set_server_socket_security(void *socket,
                                      const char *server_secret_key)
{
    int rc = 0, as_server = 1;
    rc = zmq_setsockopt(socket, ZMQ_CURVE_SERVER, &as_server,
                        sizeof(as_server));
    if(rc)
        PERROR_RET(1, "zmq_setsockopt ZMQ_CURVE_SERVER");

    rc = zmq_setsockopt(socket, ZMQ_CURVE_SECRETKEY, server_secret_key,
                        strlen(server_secret_key));
    if(rc)
        PERROR_RET(1, "zmq_setsockopt ZMQ_CURVE_SECRETKEY");

    return 0;
}


static int node_loop(struct communication_objects *communication_objs,
                     const char *database_path, int close_fds,
                     multiple_connections_t mult_conn)
{
    zmq_msg_t rcvd_msg_, out_msg_;
    zmq_msg_t *rcvd_msg = &rcvd_msg_, *out_msg = &out_msg_;
    const unsigned poll_items = 4;
    const char *auth_user_id;
    const char *outgoing_address;
    char *instance_id, *identity;
    int rc = 0;
    void *out_sock;

    database_t *db_conn = db_init_connection(database_path, 0, mult_conn);
    EXIT_ON_FALSE(db_conn, "Error trying to connect to the DB.");

    //TODO Check if synchronization is necessary to wait that the
    // classifier thread is connected.
    //rc = zmq_msg_init(msg);
    //classifier_main_thread_socket;
    long poll_timeout = -1;

    /* zmq_pollitem_t items[poll_items]; */
    /* items[0].socket = communication_objs->sub_socket; */
    /* items[1].socket = communication_objs->router_socket; */
    /* items[2].socket = communication_objs->outgoing_socket; */
    /* items[0].events = items[1].events = items[2].events = ZMQ_POLLIN; */

    zmq_pollitem_t items [] =
            { {communication_objs->sub_socket, 0, ZMQ_POLLIN | ZMQ_POLLOUT | ZMQ_POLLERR, 0}
            , {communication_objs->router_socket, 0, ZMQ_POLLIN, 0}
            , {communication_objs->outgoing_socket, 0, ZMQ_POLLIN, 0}
            , {NULL, close_fds, ZMQ_POLLIN, 0}
            };

    while(1) {
        rc = zmq_poll(items, poll_items, poll_timeout);

        if(rc <= 0) {
            if(errno == EINTR)
                continue;
            LOG(LOG_LVL_CRIT, "Poll failed:%s", zmq_strerror(errno));
            break;
        }

        // Exit
        if(items[3].revents) {
            char close_msg[100];
            read(close_fds, close_msg, 99);
            close_msg[99] = '\0';
            LOG(LOG_LVL_INFO, "%s", close_msg);
            break;
        }

        rc = zmq_msg_init(rcvd_msg);
        if(rc == -1) {
            LOG(LOG_LVL_CRIT, "MSG init failed:%s", zmq_strerror(errno));
            continue; //TODO or break?
        }

        if(items[0].revents) {
            rc = zmq_msg_recv(rcvd_msg, communication_objs->sub_socket, 0);
            if(rc == -1) {
                LOG(LOG_LVL_ERRO, "Error Receiving msg:%s", zmq_strerror(errno));
                zmq_msg_close(rcvd_msg);
                continue;
            }

            auth_user_id = zmq_msg_gets(rcvd_msg, "User-Id");
            if(auth_user_id == NULL) {
                LOG(LOG_LVL_ERRO, "Unauthenticated msg received");
                zmq_msg_close(rcvd_msg);
                continue;
            }
        }

        else if(items[1].revents) {
            identity = s_recv(communication_objs->router_socket);
            if(identity == NULL) {
                LOG(LOG_LVL_ERRO, "Could not get sender identity.");
                zmq_msg_close(rcvd_msg);
                continue;
            }

            rc = zmq_msg_recv(rcvd_msg, communication_objs->router_socket, 0);
            if(rc == -1) {
                LOG(LOG_LVL_ERRO, "Error Receiving msg:%s", zmq_strerror(errno));
                zmq_msg_close(rcvd_msg);
                free(identity);
                continue;
            }

            auth_user_id = zmq_msg_gets(rcvd_msg, "User-Id");
            if(auth_user_id == NULL) {
                LOG(LOG_LVL_ERRO, "Unauthenticated msg received");
                zmq_msg_close(rcvd_msg);
                free(identity);
                continue;
            }

            rc = db_get_instance_id_from_router_token(db_conn, auth_user_id,
                                                      &instance_id);
            if(rc != DTC_ERR_NONE) {
                LOG(LOG_LVL_ERRO, "Error retrieving instance_id from DB: %d",
                    rc);
                zmq_msg_close(rcvd_msg);
                free(identity);
                continue;
            }

            if(strncmp(identity, instance_id, strlen(instance_id)) != 0) {
                LOG(LOG_LVL_ERRO,
                    "Auth %s instance_id does not match router identity %s",
                    instance_id, identity);
                zmq_msg_close(rcvd_msg);
                free(identity);
                free(instance_id);
                continue;
            }
            free(identity);
            free(instance_id);
        }

        else if(items[2].revents) { // Probably else is enough.
            identity = s_recv(communication_objs->outgoing_socket);
            if(identity == NULL) {
                LOG(LOG_LVL_ERRO, "Error reading frame 1 of outgoing_socket");
                zmq_msg_close(rcvd_msg);
                continue;
            }

            rc = zmq_msg_recv(rcvd_msg, communication_objs->outgoing_socket, 0);
            if(rc == -1) {
                zmq_msg_close(rcvd_msg);
                free(identity);
                LOG_EXIT("Error reading second frame of pull socket");
            }

        }

        rc = zmq_msg_init(out_msg);
        if(rc == -1) {
            LOG(LOG_LVL_CRIT, "MSG init failed:%s", zmq_strerror(errno));
            zmq_msg_close(rcvd_msg);
            free(instance_id);
            continue; //TODO or break?
        }
        //
        if(items[0].revents || items[1].revents) {
            out_sock = communication_objs->incoming_socket;
            outgoing_address = strdup(auth_user_id);
        }
        else if(items[2].revents) {
            out_sock = communication_objs->router_socket;
            outgoing_address = identity;
        }

        rc = zmq_msg_copy(out_msg, rcvd_msg);
        zmq_msg_close(rcvd_msg);
        if(rc != 0) {
            LOG(LOG_LVL_ERRO, "Unable to copy the msg:%s",
                zmq_strerror(errno));
            free((void *)outgoing_address);
            continue;
        }

        rc = s_sendmore(out_sock, outgoing_address);
        if(rc == -1) {
            LOG(LOG_LVL_ERRO, "Unable to send msg: %s", zmq_strerror(errno));
            zmq_msg_close(out_msg);
            free((void *)outgoing_address);
            continue;
        }

        rc = zmq_msg_send(out_msg, out_sock, 0);
        if(rc == -1) {
            zmq_msg_close(out_msg);
            free((void *)outgoing_address);
            // TODO Not sure how to handle an error sending second part
            // of multipart msg, investigate it and remove the EXIT.
            LOG_EXIT("Unable to send msg: %s", zmq_strerror(errno));
        }
        free((void *)outgoing_address);

    }
    close(close_fds);
    zmq_close(communication_objs->sub_socket);
    zmq_close(communication_objs->router_socket);
    zmq_close(communication_objs->outgoing_socket);
    zmq_close(communication_objs->incoming_socket);
    db_close_and_free_connection(db_conn);
    LOG(LOG_LVL_INFO, "Closing the node_loop...");

    return 0;
}

// TODO check if db_is_an_authorized_key is used, remove it if it's not.

static void zap_handler(void *zap_data_)
{

    uint8_t client_key [32];
    char *aux_char;
    struct zap_handler_data *zap_data = (struct zap_handler_data *) zap_data_;
    void *sock = zap_data->socket;
    database_t *db_conn = db_init_connection(zap_data->database, 0,
                                             zap_data->multiple_connections);
    EXIT_ON_FALSE(db_conn, "Error trying to connect to the DB.");
    LOG(LOG_LVL_INFO, "Starting ZAP thread.");

    //  Process ZAP requests forever
    while (1) {
        char *version = s_recv(sock);
        if(version == NULL) {
            break;
        }
        char *sequence = s_recv(sock);
        char *domain = s_recv(sock);
        char *address = s_recv(sock);
        char *identity = s_recv(sock);
        char *mechanism = s_recv(sock);

        zmq_recv(sock, client_key, 32, 0);

        char client_key_text [42];
        zmq_z85_encode(client_key_text, client_key, 32);


        s_sendmore(sock, version);
        s_sendmore(sock, sequence);
        /* fprintf(stderr, "Version : %s\n", version); */
        /* fprintf(stderr, "Sequence: %s\n", sequence); */
        /* fprintf(stderr, "Address: %s\n", address); */
        /* fprintf(stderr, "identity: %s\n", identity); */
        /* fprintf(stderr, "mechanism: %s\n", mechanism); */

        if(strcmp("SUB_SOCKET",  domain) == 0) {
            if(DTC_ERR_NONE == db_get_new_pub_token(db_conn, client_key_text,
                                                    address,
                                                    &aux_char)) {
                s_sendmore(sock, "200");
                s_sendmore(sock, "OK");
                s_sendmore(sock, aux_char);
                free(aux_char);
                LOG(LOG_LVL_INFO, "Sub socket accepted a connection from:%s",
                    address);
            }
            else {
                s_sendmore(sock, "400");
                s_sendmore(sock, "Not an authorized master");
                s_sendmore(sock, "");
                LOG(LOG_LVL_INFO, "SUB socket rejected a connection from %s.",
                    address);
            }
        }
        else if(strcmp("ROUTER_SOCKET", domain) == 0) {
            if(DTC_ERR_NONE == db_get_new_router_token(db_conn, client_key_text,
                                                       address,
                                                       &aux_char)) {
                s_sendmore(sock, "200");
                s_sendmore(sock, "OK");
                s_sendmore(sock, aux_char);
                free(aux_char);
                LOG(LOG_LVL_INFO, "Router socket accepted a connection from:%s.",
                    address);
            }
            else {
                s_sendmore(sock, "400");
                s_sendmore(sock, "Not an authorized master");
                s_sendmore(sock, "");
                LOG(LOG_LVL_INFO, "Router socket rejected a connection from:%s.",
                    address);
            }
        }
        else {
            // This should never happen.
            s_sendmore(sock, "400");
            s_sendmore(sock, "Invalid client public key");
            s_sendmore(sock, "");
            LOG(LOG_LVL_CRIT, "Connection rejected.");
        }

        s_send(sock, "");

        free(version);
        free(sequence);
        free(domain);
        free(address);
        free(identity);
        free(mechanism);
    }
    zmq_close(sock);
    db_close_and_free_connection(db_conn);
    free(zap_data_);
    LOG(LOG_LVL_INFO, "Closing zap thread");
}
