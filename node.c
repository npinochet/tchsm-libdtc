#define _POSIX_C_SOURCE 200809L
#include <getopt.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include <zmq.h>

#include "logger/logger.h"
#include "messages.h"


struct flags {
    // Interface to open the connection.
    char *interface;

    // Port number to bind the SUB socket in.
    uint16_t sub_port;

    // Port numbre to bind the DEALER socket in.
    uint16_t dealer_port;

};

struct communication_objects {
    void *ctx;
    void *sub_socket;
    void *dealer_socket;

    // Inter threads communication.
    char *classifier_socket_address;
    void *classifier_main_thread_socket;

};

struct socket_descr {
    void *ctx;
    char *socket_address;
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
static char* configuration_to_string(const struct flags *conf){
    /* Be aware, this memory is shared among the aplication, this function
     * should be called just once or the memory of the previous calls might get
     * corrupted.
     */
    static char buff[200];

    snprintf(buff, sizeof(buff),
             "\nInterface:\t%s\nSUB port:\t%" PRIu16 "\n"
             "Dealer port:\t%" PRIu16,
             conf->interface, conf->sub_port, conf->dealer_port);
    return &buff[0];
}


// Just declarations, see definitions for documentation.
static int read_configuration(int argc, char *argv[], struct flags *conf);
static struct communication_objects *init_node(const struct flags *conf);
static struct communication_objects *create_and_bind_sockets(
        const struct flags *conf);
static int node_loop();
static int set_server_socket_security(void *socket, char *server_secret_key);
static void zap_handler (void *handler);

int main(int argc, char **argv){
    int ret_val = 0;

    // Default configuration.
    static struct flags configuration = {.interface = "eth0",
                                         .sub_port = 23194,
                                         .dealer_port = 23195};

    logger_init_stream(stderr);
    LOG(LOG_LVL_NOTI, "Logger started for %s", argv[0]);

    ret_val = read_configuration(argc, argv, &configuration);
    if(ret_val)
        return 1;

    LOG(LOG_LVL_LOG, "Logger configuration:%s",
        configuration_to_string(&configuration));

    struct communication_objects *communication_objs = init_node(&configuration);
    if(!communication_objs)
        return 1;

    return node_loop(communication_objs);
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
static int read_configuration(int argc, char *argv[], struct flags *conf) {
    int option_index = 0;
    char c;
    static struct option long_options[] = {
        {"dealer_port", required_argument, 0, 'd'},
        {"interface", required_argument, 0, 'i'},
        {"sub_port", required_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {0, 0, 0, 0}};

    while((c = getopt_long(argc, argv, ":d:i:s:v", long_options,
                           &option_index)) != -1) {
        switch(c) {
        case 'd':
            if (str_to_uint16(optarg, &conf->dealer_port)){
                LOG(LOG_LVL_CRIT,
                    "Dealer port should be an integer between 0 and 65535.")
                return 1;
            }
            break;
        case 'i':
            conf->interface = optarg;
            break;
        case 's':
            if (str_to_uint16(optarg, &conf->sub_port)){
                LOG(LOG_LVL_CRIT,
                    "SUB port should be an integer between 0 and 65535.")
                return 1;
            }
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

    return 0;
}
void handle_store_key_pub(struct op_req *op) {
    if(op->version != 1){
        LOG(LOG_LVL_ERRO, "version %" PRIu16 " not supported.");
        free(op);
        return;
    }


    free(op);
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
        free(op);
        return;
    }

    (op_handlers[op->op])(op);

    return;

}
void *classifier_thr(void *inproc_socket_descr) {
    int rc = 0;
    void *inproc_socket = NULL;
    int close_thread = 0;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;
    struct op_req *op;

    struct socket_descr *sock_descr =
        (struct socket_descr *) inproc_socket_descr;

    inproc_socket = zmq_socket(sock_descr->ctx, ZMQ_PAIR);
    PERROR_AND_EXIT_ON_FALSE(inproc_socket, "zmq_socket",
                             "Unable to create inproc socket.");
    rc = zmq_connect(inproc_socket, sock_descr->socket_address);
    PERROR_AND_EXIT_ON_FALSE(rc == 0, "zmq_connect",
                             "Unable to connect inproc socket.");
    free(sock_descr);
    LOG(LOG_LVL_NOTI, "Inproc socket connected!");

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

static void create_worker_threads(void *zmq_ctx,
                                  char *classifier_socket_address) {
    int ret;
    pthread_t pid;
    struct socket_descr *sock_descr =
        (struct socket_descr *) malloc(sizeof(struct socket_descr));
    sock_descr->ctx = zmq_ctx;
    sock_descr->socket_address = classifier_socket_address;

    ret = pthread_create(&pid, NULL, classifier_thr, sock_descr);
}

static struct communication_objects *init_node(
        const struct flags *configuration) {
    // TODO(fmontoto) Initialize the database.

    struct communication_objects *comm_objs;

    comm_objs = create_and_bind_sockets(configuration);

    create_worker_threads(comm_objs->ctx, comm_objs->classifier_socket_address);

    return comm_objs;
}

// TODO --help should print usage

/**
 * TODO
 **/
static struct communication_objects *create_and_bind_sockets(
        const struct flags *conf){

    const size_t bind_buff_length = 200;
    char bind_buff[bind_buff_length];
    struct communication_objects *ret_val =
        (struct communication_objects *) malloc(
                sizeof(struct communication_objects));
    void *sub_socket = NULL, *dealer_socket = NULL;
    int ret_value = 0;
    ret_val->classifier_socket_address = "inproc://classifier";
    // TODO check this exit on false.
    EXIT_ON_FALSE(ret_val, "No memory for communication_objects.");

    ret_val->ctx = zmq_ctx_new();
    EXIT_ON_FALSE(ret_val->ctx, "Context initialization error.");

    ret_val->classifier_main_thread_socket = zmq_socket(ret_val->ctx,
                                                        ZMQ_PAIR);
    PERROR_AND_EXIT_ON_FALSE(ret_val->classifier_main_thread_socket,
                             "zmq_socket",
                             "Unable to create classifier socket.");

    ret_value = zmq_bind(ret_val->classifier_main_thread_socket,
                         ret_val->classifier_socket_address);
    EXIT_ON_FALSE(!ret_value, "Bind failed at: %s.",
                  ret_val->classifier_socket_address);

    void *handler = zmq_socket (ret_val->ctx, ZMQ_REP);
    EXIT_ON_FALSE(handler, "ZAP_HANDLER socket error.")
    ret_value = zmq_bind (handler, "inproc://zeromq.zap.01");
    EXIT_ON_FALSE(!ret_value, "ZQA_HANDLER bind error.");
    /*void *zap_thread =*/ zmq_threadstart (&zap_handler, handler);





    ret_val->sub_socket = zmq_socket(ret_val->ctx, ZMQ_SUB);
    sub_socket = ret_val->sub_socket;
    PERROR_AND_EXIT_ON_FALSE(sub_socket, "zmq_socket:",
                             "Unable to create sub socket.");

    ret_val->dealer_socket = zmq_socket(ret_val->ctx, ZMQ_DEALER);
    dealer_socket = ret_val->dealer_socket;
    PERROR_AND_EXIT_ON_FALSE(dealer_socket, "zmq_socket:",
                             "Unable to create socket.");

    char *server_secret_key = "kS=N$zQ%^yv8lp6J%e]z&Eqzkje+Hh(2pD1dffMb";
    //char *server_public_key = "}L#cv]<CVY@.h3}-G(<4pky><w1]H$V?c^R*91VK";

    if(set_server_socket_security(sub_socket, server_secret_key) ||
        set_server_socket_security(dealer_socket, server_secret_key))
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
                         conf->interface, conf->dealer_port);
    if(ret_value >= bind_buff_length){
        LOG(LOG_LVL_CRIT, "Bind buffer too small (%d), required: %d.",
            bind_buff_length, ret_value);
        exit(1);
    }

    ret_value = zmq_bind(dealer_socket, bind_buff);
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

static void zap_handler (void *handler)
{
    char *client_public = "E!okhRB>r7!&T(ORk#(tncmcW-gJzA4y4G[=lm9o";
    //  Process ZAP requests forever
    while (1) {
        char *version = s_recv (handler);
        if (!version)
            break;          //  Terminating

        char *sequence = s_recv (handler);
        char *domain = s_recv (handler);
        char *address = s_recv (handler);
        char *identity = s_recv (handler);
        char *mechanism = s_recv (handler);
        uint8_t client_key [32];
        int size = zmq_recv (handler, client_key, 32, 0);
        printf("size:%d\n", size);
        //assert (size == 32);

        char client_key_text [41];
        zmq_z85_encode (client_key_text, client_key, 32);

        printf("%s\n%s\n%s\n%s\n%s\n", sequence, domain, address, identity,
               mechanism);

        printf("%.*s\n", 32, client_key_text);

        //assert (streq (version, "1.0"));
        //assert (streq (mechanism, "CURVE"));
        //assert (streq (identity, "IDENT"));

        s_sendmore (handler, version);
        s_sendmore (handler, sequence);

        if (!strcmp(client_key_text, client_public)) {
            s_sendmore (handler, "200");
            s_sendmore (handler, "OK");
            s_sendmore (handler, "anonymous");
            s_send     (handler, "");
        }
        else {
            s_sendmore (handler, "400");
            s_sendmore (handler, "Invalid client public key");
            s_sendmore (handler, "");
            s_send     (handler, "");
        }
        free (version);
        free (sequence);
        free (domain);
        free (address);
        free (identity);
        free (mechanism);
    }
    zmq_close (handler);
}



