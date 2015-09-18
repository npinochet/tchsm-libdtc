#define _POSIX_C_SOURCE 200809L

#include <getopt.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h> // TODO Just for the sleep, remove it.

#include <libconfig.h>
#include <zmq.h>

#include <tc.h>

#include "dtc.h"
#include "err.h"
#include "messages.h"
#include "utilities.h"

#ifndef NDEBUG
    #include "logger/logger.h"
    #define LOG_DEBUG(level, format, ...) \
        LOG(level, format, ## __VA_ARGS__)
#else
    #define LOG_DEBUG(level, format, ...) \
        do {}while(0);
#endif


const uint16_t DEFAULT_TIMEOUT = 10;


struct dtc_ctx {

    char *server_id;

    // Timeout for the operations.
    uint16_t timeout;

    // Communication
    void *zmq_ctx;
    void *pub_socket;
    void *router_socket;
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

struct communication_objects {
    void *ctx;
    void *sub_socket;
    void *dealer_socket;
};

static void free_nodes(unsigned int cant_nodes, struct node_info *node) {
    unsigned int i;
    if(!node)
        return;
    for(i = 0; i < cant_nodes; i++){
        if(node[i].ip)
            free(node[i].ip);
    }
    free(node);
}

static void free_conf(struct configuration *conf) {
    if(!conf)
        return;
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

/* Return a human readable version of the configuration */
static char* configuration_to_string(const struct configuration *conf){
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

static void free_nodes(unsigned int cant_nodes, struct node_info *node);
static int set_client_socket_security(void *socket,
                                      const char *client_secret_key,
                                      const char *client_public_key);
static int create_connect_sockets();
static int read_configuration_file(struct configuration *conf);

int main(int argc, char **argv){
    int ret_val = 0;
    public_key_t **info = NULL;

    logger_init_stream(stderr);
    LOG(LOG_LVL_NOTI, "Logger started for %s", argv[0]);

    dtc_ctx_t *ctx = dtc_init(NULL, &ret_val);

    printf("Init ret: %d\n", ret_val);
    if(ret_val != DTC_ERR_NONE)
        return 1;

    sleep(1);
    ret_val = dtc_generate_key_shares(ctx, "hola_id", 1024, 2, 2, info);
    printf("Generate: %d\n", ret_val);
    if(ret_val != DTC_ERR_NONE)
        return 1;

    return 0;
}

dtc_ctx_t *dtc_init(const char *config_file, int *err) {
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

    return ret;

err_exit:
    free(ret);
    free_conf(&conf);
    return NULL;
}


int dtc_generate_key_shares(dtc_ctx_t *ctx, const char *key_id, size_t bit_size,
                            uint16_t threshold, uint16_t cant_nodes,
                            public_key_t **info) {
    struct op_req operation;
    struct store_key_pub store_key_pub;
    union command_args *args = (union command_args *) &store_key_pub;
    size_t msg_size = 0;
    char *msg_data = NULL;
    int ret;
    zmq_msg_t msg_;
    zmq_msg_t *msg = &msg_;

    key_share_t **key_shares = NULL;
    key_metainfo_t *key_metainfo = NULL;

    operation.version = 1;
    operation.op = OP_STORE_KEY_PUB;
    store_key_pub.server_id = ctx->server_id;
    store_key_pub.key_id = key_id;
    operation.args = args;

    msg_size = serialize_op_req(&operation, &msg_data);
    if(!msg_size)
        return DTC_ERR_SERIALIZATION;

    printf("%s\n", msg_data);

    ret = zmq_msg_init_data(msg, msg_data, msg_size, NULL, NULL);
    if(ret) {
        LOG_DEBUG(LOG_LVL_CRIT, "zmq_msg_init_data failed");
        goto err_exit;
    }

    ret = zmq_msg_send(msg, ctx->pub_socket, 0);
    if(ret  == -1) {
        LOG_DEBUG(LOG_LVL_CRIT, "zmq_msg_send:%s\n%s", strerror(errno),
                  "Error sending the message.");
        return DTC_ERR_COMMUNICATION;
    }

    key_shares = tc_generate_keys(&key_metainfo, bit_size, threshold,
                                  cant_nodes);

    zmq_msg_init(msg);
    ret = zmq_msg_recv(msg, ctx->router_socket, 0);

    printf("%.*s\n", ret, zmq_msg_data(msg));
    zmq_msg_close(msg);

    return DTC_ERR_NONE;

err_exit:
    free(msg_data);
    return ret;
}



static int create_connect_sockets(const struct configuration *conf,
                                  struct dtc_ctx *ctx) {
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
                  strerror(errno));
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
/*
    ret_val = zmq_setsockopt(router_socket, ZMQ_IDENTITY, "soy_server",
                             10);
    if(ret_val != 0) {
        ret = DTC_ERR_ZMQ_CURVE;
        goto err_exit;
    }
*/
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
                                      const char *client_public_key) {
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
static int read_configuration_file(struct configuration *conf) {
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

    return DTC_ERR_NONE;

err_exit:
    free_nodes(cant_nodes, conf->nodes);
    cant_nodes = 0;
    config_destroy(&cfg);
    return ret;
}
