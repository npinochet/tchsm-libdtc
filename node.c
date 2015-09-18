#define _POSIX_C_SOURCE 200809L
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <libconfig.h>
#include <zmq.h>

#include "database.h"
#include "err.h"
#include "logger/logger.h"
#include "messages.h"
#include "utilities.h"

struct master_info {
    // master_id.
    char *id;

    // master public key.
    char *public_key;
};

struct configuration {

    char *configuration_file;

    // Interface to open the connection.
    char *interface;

    // Path to the file with the database.
    char *database;

    // Port number to bind the SUB socket in.
    uint16_t sub_port;

    // Port number to bind the ROUTER socket in.
    uint16_t router_port;

    size_t cant_masters;

    struct master_info *masters;

    char *public_key;

    char *private_key;
};

struct communication_objects {
    void *ctx;
    void *sub_socket;
    void *router_socket;

    // Inter threads communication.
    char *classifier_socket_address;
    void *classifier_main_thread_socket;

};

struct classifier_data {
    void *ctx;
    void *router_socket;
    char *socket_address;
};

struct zap_handler_data {
    // Inproc socket.
    void *socket;

    // Path to the database file.
    char *database;
};

/* Utils */

/* Safe conversion from str to uint16_t */
int str_to_uint16(const char *str, uint16_t *res){
    errno = 0;
    unsigned long int result = strtoul(str, NULL, 10);
    if (errno == ERANGE || result > UINT16_MAX)
        return 1;
    *res = (uint16_t)result;
    return 0;
}

/* Return a human readable version of the configuration */
static char* configuration_to_string(const struct configuration *conf){
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
static int node_loop();
static int set_server_socket_security(void *socket, char *server_secret_key);
static void zap_handler (void *handler);

static void update_database(struct configuration *conf) {
    unsigned i;
    database_t *db_conn = db_init_connection(conf->database);
    EXIT_ON_FALSE(db_conn, "Error trying to connect to the database.");

    for(i = 0; i < conf->cant_masters; i++) {
        if(db_add_new_server(db_conn, conf->masters[i].id,
                             conf->masters[i].public_key))
            LOG_EXIT("Error adding new server.");
    }

    EXIT_ON_FALSE(db_update_servers(db_conn) == 0, "Update servers failed.");
}
int main(int argc, char **argv){
    int ret_val = 0;

    // Default configuration.
    static struct configuration configuration =
            {.configuration_file = "./config"};

    logger_init_stream(stderr);
    LOG(LOG_LVL_NOTI, "Logger started for %s", argv[0]);

    ret_val = read_configuration(argc, argv, &configuration);
    if(ret_val)
        return 1;

    LOG(LOG_LVL_LOG, "Logger configuration:%s",
        configuration_to_string(&configuration));

    update_database(&configuration);

    struct communication_objects *communication_objs =
            init_node(&configuration);
    if(!communication_objs)
        return 1;

    return node_loop(communication_objs);
}


/**
 * Read the configuration file an load its definitions into conf.
 *
 * @param conf Configuration struct to load the data into.
 *
 * @return DTC_ERR_NONE on success, a proper error code on error.
 *
 **/
static int read_configuration_file(struct configuration *conf) {
    config_t cfg;
    config_setting_t *root, *masters, *node, *element;
    int cant_masters = 0, rc;
    unsigned int i = 0;
    int ret = DTC_ERR_CONFIG_FILE;

    config_init(&cfg);

    EXIT_ON_FALSE(CONFIG_TRUE == config_read_file(&cfg,
                                                  conf->configuration_file),
                  "%s:%d - %s\n", config_error_file(&cfg),
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

    rc = lookup_uint16_conf_element(node, "router_port", &conf->router_port);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Unable to retrieve router_port.");

    rc = lookup_uint16_conf_element(node, "sub_port", &conf->sub_port);
    EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Unable to retrieve sub_port.");

    for(i = 0; i < cant_masters; i++) {
        element = config_setting_get_elem(masters, i);
        EXIT_ON_FALSE(element, "Error getting element %u from masters", i);

        ret = lookup_string_conf_element(element, "public_key",
                                         &conf->masters[i].public_key);
        EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Exit.");

        ret = lookup_string_conf_element(element, "id", &conf->masters[i].id);
        EXIT_ON_FALSE(ret == DTC_ERR_NONE, "Exit.");
    }

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
                               struct configuration *conf) {
    int option_index = 0;
    char c;
    static struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}};

    while((c = getopt_long(argc, argv, ":d:i:s:l:v", long_options,
                           &option_index)) != -1) {
        switch(c) {
        case 'c':
            conf->configuration_file = optarg;
            break;
        case 'v':
            LOG(LOG_LVL_CRIT, "Not implemented yet :(")
            break;
        case ':':
            LOG(LOG_LVL_CRIT, "Missing parameter for %c (%s).", optopt,
                argv[optind -1 ]);
            return 1;
        case '?':
            LOG(LOG_LVL_CRIT, "Invalid option found. (%s).", argv[optind - 1]);
            break;
        case 1:
            break;
        default:
            break;
        }
    }
    read_configuration_file(conf);

    return 0;
}

void handle_store_key_pub(struct op_req *op) {
    if(op->version != 1){
        LOG(LOG_LVL_ERRO, "version %" PRIu16 " not supported.");
        free(op);
        return;
    }








    delete_op_req(op);
}
void classify_and_handle_operation(struct op_req *op) {
    #define TOTAL_SUPPORTED_OPS 1
    uint16_t supported_operations[TOTAL_SUPPORTED_OPS] = {OP_STORE_KEY_PUB};
    static void (*const op_handlers[TOTAL_SUPPORTED_OPS]) (struct op_req *op) =
        {handle_store_key_pub};

    unsigned i;
    for(i = 0; i < TOTAL_SUPPORTED_OPS; i++) {
        if(op->op == supported_operations[i])
            break;
    }
    if(i == TOTAL_SUPPORTED_OPS) {
        LOG(LOG_LVL_ERRO, "Operation %" PRIu16 " not supported.", op->op);
        delete_op_req(op);
        return;
    }

    (op_handlers[op->op])(op);

    return;

}
void *classifier_thr(void *classifier_thread_data) {
    int rc = 0;
    void *inproc_socket = NULL;
    int close_thread = 0;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;
    struct op_req *op;

    struct classifier_data *thr_data =
        (struct classifier_data *) classifier_thread_data;

    inproc_socket = zmq_socket(thr_data->ctx, ZMQ_PAIR);
    PERROR_AND_EXIT_ON_FALSE(inproc_socket, "zmq_socket",
                             "Unable to create inproc socket.");
    rc = zmq_connect(inproc_socket, thr_data->socket_address);
    PERROR_AND_EXIT_ON_FALSE(rc == 0, "zmq_connect",
                             "Unable to connect inproc socket.");
    free(classifier_thread_data);
    LOG(LOG_LVL_NOTI, "Inproc classifier socket connected!");

    while(!close_thread) {
        rc = zmq_msg_init(msg);
        PERROR_AND_EXIT_ON_FALSE(rc == 0, "zmq_msg_init",
                                 "Unable to init msg.");

        rc = zmq_msg_recv(msg, inproc_socket, 0);
        if(rc == -1){
            PERROR_LOG(LOG_LVL_ERRO, "zmq_msg_recv",
                       "Receive message failed.");
            zmq_msg_close(msg);
            continue;
        }

        printf("Classifier:\n%.*s\n", rc, (char *) zmq_msg_data(msg));
        op = unserialize_op_req(zmq_msg_data(msg), rc);
        if(op == NULL) {
            LOG(LOG_LVL_ERRO, "Unable to unserialize the received msg.");
            zmq_msg_close(msg);
            continue;
        }

        classify_and_handle_operation(op);

        rc = zmq_msg_close(msg);
        if(rc)
            PERROR_LOG(LOG_LVL_ERROR, "zmq_msg_close",
                       "Error closing the msg,");
    }
    return NULL;
}

static void create_classifier_thread(void *zmq_ctx, void *router_socket,
                                     char *classifier_socket_address) {
    int ret;
    pthread_t pid;
    struct classifier_data *classifier_data =
        (struct classifier_data *) malloc(sizeof(struct classifier_data));
    classifier_data->ctx = zmq_ctx;
    classifier_data->socket_address = classifier_socket_address;

    ret = pthread_create(&pid, NULL, classifier_thr, classifier_data);
}

static struct communication_objects *init_node(
        const struct configuration *configuration) {
    // TODO(fmontoto) Initialize the database.

    struct communication_objects *comm_objs;

    comm_objs = create_and_bind_sockets(configuration);

    create_classifier_thread(comm_objs->ctx, comm_objs->router_socket,
                             comm_objs->classifier_socket_address);

    // The classifier thread will take ownership of the router_socket,
    // as sockets are not intended to be shared by threads, this prevent to use
    // it from a different thread.
    comm_objs->router_socket = NULL;

    return comm_objs;
}

// TODO --help should print usage

static void set_zap_security(void *zmq_ctx, char *database) {

    int ret_value;
    struct zap_handler_data *zap_data =
        (struct zap_handler_data *) malloc(sizeof(struct zap_handler_data));
    EXIT_ON_FALSE(zap_data, "malloc failed for zap_handler_data.");

    zap_data->database = database;
    zap_data->socket = zmq_socket (zmq_ctx, ZMQ_REP);
    EXIT_ON_FALSE(zap_data->socket, "ZAP_HANDLER socket error.")

    ret_value = zmq_bind (zap_data->socket, "inproc://zeromq.zap.01");
    EXIT_ON_FALSE(ret_value == 0, "ZQA_HANDLER bind error.")
    zmq_threadstart (&zap_handler, zap_data);
}
/**
 * TODO
 **/
static struct communication_objects *create_and_bind_sockets(
        const struct configuration *conf){

    const size_t bind_buff_length = 200;
    char bind_buff[bind_buff_length];
    struct communication_objects *ret_val =
        (struct communication_objects *) malloc(
                sizeof(struct communication_objects));

    void *sub_socket = NULL, *router_socket = NULL;
    int ret_value = 0;
    ret_val->classifier_socket_address = "inproc://classifier";

    ret_val->ctx = zmq_ctx_new();
    EXIT_ON_FALSE(ret_val->ctx, "Context initialization error.");

    set_zap_security(ret_val->ctx, conf->database);

    // Socket to send received messages for classification.
    ret_val->classifier_main_thread_socket = zmq_socket(ret_val->ctx,
                                                        ZMQ_PAIR);
    PERROR_AND_EXIT_ON_FALSE(ret_val->classifier_main_thread_socket,
                             "zmq_socket",
                             "Unable to create classifier socket.");

    ret_value = zmq_bind(ret_val->classifier_main_thread_socket,
                         ret_val->classifier_socket_address);
    EXIT_ON_FALSE(!ret_value, "Bind failed at: %s.",
                  ret_val->classifier_socket_address);

    ret_val->sub_socket = zmq_socket(ret_val->ctx, ZMQ_SUB);
    sub_socket = ret_val->sub_socket;
    PERROR_AND_EXIT_ON_FALSE(sub_socket, "zmq_socket:",
                             "Unable to create sub socket.");

    ret_value = zmq_setsockopt(sub_socket, ZMQ_ZAP_DOMAIN, "SUB_SOCKET", 10);
    PERROR_AND_EXIT_ON_FALSE(ret_value == 0, "zmq_setsockopt",
                             "ZMQ_ZAP_DOMAIN failed.");

    ret_val->router_socket = zmq_socket(ret_val->ctx, ZMQ_ROUTER);
    router_socket = ret_val->router_socket;
    PERROR_AND_EXIT_ON_FALSE(router_socket, "zmq_socket:",
                             "Unable to create socket.");
    ret_value = zmq_setsockopt(router_socket, ZMQ_ZAP_DOMAIN, "ROUTER_SOCKET",
                               13);
    PERROR_AND_EXIT_ON_FALSE(ret_value == 0, "zmq_setsockopt",
                             "ZMQ_ZAP_DOMAIN failed for router socket.");

    ret_value = zmq_setsockopt(router_socket, ZMQ_IDENTITY, conf->public_key,
                               strlen(conf->public_key));
    PERROR_AND_EXIT_ON_FALSE(ret_value == 0, "zmq_setsockopt",
                             "ZMQ_IDENTITY failed for router socket.");

    if(set_server_socket_security(sub_socket, conf->private_key) ||
        set_server_socket_security(router_socket, conf->private_key))
        exit(1);

    //TODO(fmontoto) Dumping both bind addresses is the same code, refactor
    //into a function?
    ret_value = snprintf(&bind_buff[0], bind_buff_length, "tcp://%s:%d",
                         conf->interface, conf->sub_port);
    if(ret_value >= bind_buff_length){
        LOG(LOG_LVL_CRIT, "Bind buffer too small (%d), required: %d.",
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
        LOG(LOG_LVL_CRIT, "Bind buffer too small (%d), required: %d.",
            bind_buff_length, ret_value);
        exit(1);
    }

    ret_value = zmq_bind(router_socket, bind_buff);
    LOG(LVL_NOTI, "Both socket binded, node ready to talk with the Master.");
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
static int set_server_socket_security(void *socket, char *server_secret_key){
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

static int node_loop(struct communication_objects *communication_objs){
    zmq_msg_t rcvd_msg_;
    zmq_msg_t *rcvd_msg = &rcvd_msg_;
    int rc = 0;

    //TODO Check if synchronization is necessary to wait that the
    // classifier thread is connected.
    //rc = zmq_msg_init(msg);
    //classifier_main_thread_socket;
    while(1){
        rc = zmq_msg_init(rcvd_msg);
        if(rc == -1)
            PERROR_RET(1, "zmq_msg_init");

        rc = zmq_msg_recv(rcvd_msg, communication_objs->sub_socket, 0);
        if(rc == -1){
            PERROR_LOG(LOG_LVL_ERRO, "zmq_msg_recv",
                       "Receive message failed.");
            zmq_msg_close(rcvd_msg);
            continue;
        }

        printf("holi:%.*s\n", rc, zmq_msg_data(rcvd_msg));
        rc = zmq_msg_send(rcvd_msg,
                          communication_objs->classifier_main_thread_socket, 0);
        if(rc == -1) {
            PERROR_LOG(LOG_LVL_ERRO, "zmq_msg_send",
                       "Unable to pass the message to the classifier thread.");
            zmq_msg_close(rcvd_msg);
            continue;
        }
    }

    return 0;
}

//  Receive 0MQ string from socket and convert into C string
//
//  Caller must free returned string. Returns NULL if the context
//  is being terminated.
char *s_recv (void *socket) {
    char buffer [256];
    int size = zmq_recv(socket, buffer, 255, 0);
    if (size == -1)
        return NULL;
    if (size > 255)
        size = 255;
    buffer [size] = 0;
    return strdup (buffer);
}

//  Convert C string to 0MQ string and send to socket
int s_send(void *socket, const char *string) {
    int size = zmq_send(socket, string, strlen(string), 0);
    return size;
}

//  Sends string as 0MQ string, as multipart non-terminal
int s_sendmore(void *socket, const char *string) {
    int size = zmq_send (socket, string, strlen(string), ZMQ_SNDMORE);
    return size;
}

static int is_an_authorized_publisher(database_t *conn, const char *key) {
    return db_is_an_authorized_key(conn, key) == 1;
}

static void zap_handler(void *zap_data_)
{

    uint8_t client_key [32];
    char *aux_char;
    int ret;
    struct zap_handler_data *zap_data = (struct zap_handler_data *) zap_data_;
    void *sock = zap_data->socket;
    database_t *db_conn = db_init_connection(zap_data->database);
    EXIT_ON_FALSE(db_conn, "Error trying to connect to the DB.");
    LOG(LOG_LVL_LOG, "Starting ZAP thread.");

    //  Process ZAP requests forever
    while (1) {
        char *version = s_recv(sock);
        char *sequence = s_recv(sock);
        char *domain = s_recv(sock);
        char *address = s_recv(sock);
        char *identity = s_recv(sock);
        char *mechanism = s_recv(sock);
        int size = zmq_recv(sock, client_key, 32, 0);

        LOG(LOG_LVL_NOTI, "Message of size: %d, sequence number: %s,"
                          "domain: %s, address: %s, identity: %s, "
                          "mechanism: %s. received.",size, sequence, domain,
                          address, identity, mechanism);

        char client_key_text [42];
        zmq_z85_encode(client_key_text, client_key, 32);

        //printf("%s\n", client_key_text);

        s_sendmore(sock, version);
        s_sendmore(sock, sequence);

        if(strcmp("SUB_SOCKET",  domain) == 0 &&
            is_an_authorized_publisher(db_conn, client_key_text)) {
            s_sendmore(sock, "200");
            s_sendmore(sock, "OK");
            s_sendmore(sock, client_key_text);
            LOG(LOG_LVL_LOG, "Sub socket accepted a new connection.");
        }
        else if(strcmp("ROUTER_SOCKET", domain) == 0) {
            ret = db_get_new_temp_token(db_conn, client_key_text, &aux_char);
            if(ret == DTC_ERR_NONE) {
                s_sendmore(sock, "200");
                s_sendmore(sock, "OK");
                s_sendmore(sock, aux_char);
                free(aux_char);
                LOG(LOG_LVL_LOG, "Router socket accepted a new connection.");
            }
            else {
                s_sendmore(sock, "400");
                s_sendmore(sock, "Not an authorized master");
                s_sendmore(sock, "");
                LOG(LOG_LVL_LOG, "Router socket rejected a connection.");
            }
        }
        else {
            s_sendmore(sock, "400");
            s_sendmore(sock, "Invalid client public key");
            s_sendmore(sock, "");
            LOG(LOG_LVL_LOG, "Connection rejected.");
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
}
