#define _GNU_SOURCE
#define DHCP_LOG_FILE "/var/log/dhcpmasq.txt"

#include <microhttpd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/types.h>
#include <time.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <sys/time.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <dirent.h>
#include "dhcp_event.h"
#include "mud_manager.h"

#define X509_HTTP_PORT 8888
#define CERT_STORAGE_DIR "/var/state/osmud/certificates"
static pthread_mutex_t tmpfile_mutex = PTHREAD_MUTEX_INITIALIZER;



typedef struct {
    char *data;
    size_t size;
} PostContext;


// eliminate all temporary files related to VC processing
void clear_all_temp_state() {
    const char *tmp_dir = "/tmp";
    pthread_mutex_lock(&tmpfile_mutex);
    DIR *dir = opendir(tmp_dir);
    if (!dir) return;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "vc_", 3) == 0 ||
            strncmp(entry->d_name, "nonce_", 6) == 0 ||
            strncmp(entry->d_name, "mudurl_", 7) == 0 ||
            strncmp(entry->d_name, "dhcp_event_", 11) == 0) {

            char full_path[512];
            snprintf(full_path, sizeof(full_path), "%s/%s", tmp_dir, entry->d_name);
            unlink(full_path);
            printf("Removed stale file: %s\n", full_path);
        }
    }
    closedir(dir);
    pthread_mutex_unlock(&tmpfile_mutex);
}

static void *process_cert_async_thread(void *arg);

const char *strip_utf8_prefix(const char *str) {
    const char *prefix = "UTF8String:";
    size_t prefix_len = strlen(prefix);
    if (strncmp(str, prefix, prefix_len) == 0) {
        return str + prefix_len;
    }
    return str;
}



// Ensure certificate directory exists
static void ensure_cert_dir() {
    struct stat st = {0};
    if (stat(CERT_STORAGE_DIR, &st) == -1) {
        mkdir(CERT_STORAGE_DIR, 0755);
    }
}

bool verify_signature(const char *ip) {
    char nonce_path[256], sig_path[256], cert_path[256];
    snprintf(nonce_path, sizeof(nonce_path), "/tmp/nonce_%s", ip);
    snprintf(sig_path, sizeof(sig_path), "/tmp/signed_nonce_%s", ip);
    snprintf(cert_path, sizeof(cert_path), "%s/%s.pem", CERT_STORAGE_DIR, ip);

    pthread_mutex_lock(&tmpfile_mutex);

    // Load the certificate
    FILE *cert_fp = fopen(cert_path, "r");
    if (!cert_fp) return false;

    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);
    if (!cert) return false;

    EVP_PKEY *pubkey = X509_get_pubkey(cert);
    X509_free(cert);
    if (!pubkey) return false;

    // Read the nonce
    FILE *nonce_fp = fopen(nonce_path, "rb");
    if (!nonce_fp) {
        EVP_PKEY_free(pubkey);
        return false;
    }
    fseek(nonce_fp, 0, SEEK_END);
    long nonce_len = ftell(nonce_fp);
    rewind(nonce_fp);
    unsigned char *nonce_data = malloc(nonce_len);
    fread(nonce_data, 1, nonce_len, nonce_fp);
    fclose(nonce_fp);

    // Read the signature
    FILE *sig_fp = fopen(sig_path, "rb");
    if (!sig_fp) {
        EVP_PKEY_free(pubkey);
        free(nonce_data);
        return false;
    }
    fseek(sig_fp, 0, SEEK_END);
    long sig_len = ftell(sig_fp);
    rewind(sig_fp);
    unsigned char *sig_data = malloc(sig_len);
    fread(sig_data, 1, sig_len, sig_fp);
    fclose(sig_fp);

    // Verify the signature
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    bool result = false;

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) == 1 &&
        EVP_DigestVerifyUpdate(mdctx, nonce_data, nonce_len) == 1 &&
        EVP_DigestVerifyFinal(mdctx, sig_data, sig_len) == 1) {
        result = true;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pubkey);
    free(nonce_data);
    free(sig_data);

    if (result) {
        unlink(nonce_path);
        unlink(sig_path);
    }
    pthread_mutex_unlock(&tmpfile_mutex);

    return result;
}


DhcpEvent *load_event_from_file(const char *ip) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/dhcp_event_%s", ip);
    printf("Loading event from file: %s\n", path);
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    char line[1024];
    if (!fgets(line, sizeof(line), f)) {
        fclose(f);
        return NULL;
    }
    fclose(f);

    DhcpEvent *event = calloc(1, sizeof(DhcpEvent));
    char *array[9] = {0};
    int i = 0;
    char *tmp = strdup(line);
    char *token = strtok(tmp, "|\t\n\r");
    while (token && i < 8) {
        array[i++] = strdup(token);
        token = strtok(NULL, "|\t\n\r");
    }
    free(tmp);

    event->date = array[0];
    event->lanDevice = array[1];
    event->dhcpRequestFlags = array[2];
    event->dhcpVendor = array[3];
    event->macAddress = array[4];
    event->ipAddress = array[5];
    event->mudFileURL = (strcmp(array[6], "-") == 0) ? NULL : array[6];
    event->hostName = (strcmp(array[7], "-") == 0) ? NULL : array[7];
    event->action = NEW;

    return event;
}

void free_dhcp_event(DhcpEvent *event) {
    if (!event) return;
    free(event->date);
    free(event->lanDevice);
    free(event->dhcpRequestFlags);
    free(event->dhcpVendor);
    free(event->macAddress);
    free(event->ipAddress);
    if (event->mudFileURL) free(event->mudFileURL);
    free(event);
}


static void generate_nonce_for_ip(const char *ip, char *nonce_out, size_t size) {
    srand(time(NULL) ^ getpid());  // inizialization more random
    snprintf(nonce_out, size, "%08x%08x", rand(), rand());

    // save nonce to file binded to the IP
    char path[256];
    snprintf(path, sizeof(path), "/tmp/nonce_%s", ip);
    pthread_mutex_lock(&tmpfile_mutex);
    FILE *f = fopen(path, "w");
    if (f) {
        fprintf(f, "%s", nonce_out);
        fclose(f);
    } else {
        perror("fopen nonce file");
    }
    pthread_mutex_unlock(&tmpfile_mutex);
}

void save_event_to_file(const DhcpEvent *event) {
    char path[256];
    snprintf(path, sizeof(path), "/tmp/dhcp_event_%s", event->ipAddress);

    // prepare the content to save
    char new_content[1024];
    snprintf(new_content, sizeof(new_content), "%s|%s|%s|%s|%s|%s|%s|%s\n",
        event->date, event->lanDevice, event->dhcpRequestFlags,
        event->dhcpVendor, event->macAddress, event->ipAddress, 
        event->mudFileURL ? event->mudFileURL : "-",
        event->hostName ? event->hostName : "-");

    // if the file already exists, check if the IP is already present
    bool is_new_ip = true;
    FILE *existing = fopen(path, "r");
    if (existing) {
        char buffer[1024];
        if (fgets(buffer, sizeof(buffer), existing)) {
            // Extract the IP from the existing event
            char *line_copy = strdup(buffer);
            char *token;
            int field = 0;
            char *saved_ip = NULL;

            token = strtok(line_copy, "|\t\n\r");
            while (token != NULL) {
                field++;
                if (field == 6) {
                    saved_ip = strdup(token);
                    break;
                }
                token = strtok(NULL, "|\t\n\r");
            }

            if (saved_ip && strcmp(saved_ip, event->ipAddress) == 0) {
                is_new_ip = false;
            }

            free(saved_ip);
            free(line_copy);
        }
        fclose(existing);
    }

    if (!is_new_ip) {
        printf("Event for IP %s already exist.\n", event->ipAddress);
        return;
    }

    if (is_new_ip) {
        // if this is a new IP, we block traffic for this IP except to OSMUD server
        block_device_traffic_except_osmud(event->ipAddress);
    }

    // write the new content to the file
    FILE *f = fopen(path, "w");
    if (!f) {
        perror("fopen event save");
        return;
    }
    fputs(new_content, f);
    fclose(f);
    printf("Event saved for IP %s\n", event->ipAddress);
}



void block_device_traffic_except_osmud(const char *ip) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "iptables -A FORWARD -p tcp -s %s -d 192.168.10.1 --dport 8888 -j ACCEPT", ip);
    system(cmd);
    sprintf(cmd, "iptables -A FORWARD -s %s -j DROP", ip);
    system(cmd);
    printf("Blocked all traffic from %s except to OSMUD server.\n", ip);
}

void unblock_device_traffic(const char *ip) {
    char cmd[256];
    int i;

    // Remove all DROP rules from MUD_CHAIN
    for (i = 0; i < 10; i++) {
        snprintf(cmd, sizeof(cmd), "iptables -D MUD_CHAIN -s %s -j DROP 2>/dev/null", ip);
        if (system(cmd) != 0) break;  // ends when no more rules to remove
    }

    // Remove all DROP rules from FORWARD chain
    for (i = 0; i < 10; i++) {
        snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -s %s -j DROP 2>/dev/null", ip);
        if (system(cmd) != 0) break;
    }

    printf("Unblocked traffic for %s (MUD_CHAIN and FORWARD)\n", ip);
}


static char* extract_mud_url_from_cert(const char *pemfile) {

    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "openssl x509 -in %s -noout -text | grep -A1 '1.3.6.1.5.5.7.1.25' | tail -n1 | awk '{$1=$1;print}'",
        pemfile);

    FILE *fp = popen(cmd, "r");
    if (!fp) {
        fprintf(stderr, "Error running openssl to extract MUD URL\n");
        return NULL;
    }

    char buffer[512] = {0};
    if (!fgets(buffer, sizeof(buffer), fp)) {
        pclose(fp);
        return NULL;
    }
    pclose(fp);

    // Remove trailing newline
    buffer[strcspn(buffer, "\r\n")] = '\0';

    if (strlen(buffer) == 0) {
        return NULL;
    }

        // Remove trailing newline
    buffer[strcspn(buffer, "\r\n")] = '\0';

    // Remove leading dots and hashes
    char *mud_url = buffer;
    while (*mud_url == '.' || *mud_url == '#') mud_url++;

    if (strlen(mud_url) == 0) {
        return NULL;
    }

    return strdup(mud_url);
}




// Save certificate received from HTTP POST
static void save_certificate(const char *ip, const char *data, size_t size) {
    ensure_cert_dir();

    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s.pem", CERT_STORAGE_DIR, ip);
    pthread_mutex_lock(&tmpfile_mutex);

    FILE *f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        return;
    }

    fwrite(data, 1, size, f);
    fclose(f);

    printf("Saved certificate for IP %s -> %s\n", ip, filename);
    pthread_mutex_unlock(&tmpfile_mutex);

    // async thread to process the cert
    char *ip_copy = strdup(ip);
    pthread_t tid;
    if (pthread_create(&tid, NULL, process_cert_async_thread, ip_copy) == 0) {
        pthread_detach(tid);
    } else {
        perror("pthread_create");
        free(ip_copy);
    }
}



char *verify_certificate_for_ip(const char *ipAddress) {
    if (!ipAddress) return NULL;
    printf("Verifying certificate for IP %s\n", ipAddress);
    char cert_path[256];
    snprintf(cert_path, sizeof(cert_path), "%s/%s.pem", CERT_STORAGE_DIR, ipAddress);

    printf("Verifying certificate for IP %s at %s\n", ipAddress, cert_path);

    pthread_mutex_lock(&tmpfile_mutex);
    FILE *cert_fp = fopen(cert_path, "r");
    if (!cert_fp) {
        pthread_mutex_unlock(&tmpfile_mutex);
        return NULL;
    }

    X509 *cert = PEM_read_X509(cert_fp, NULL, NULL, NULL);
    fclose(cert_fp);
    if (!cert) return NULL;

    // Verify the certificate against the system's CA store
    X509_STORE *store = X509_STORE_new();
    if (!store) {
        X509_free(cert);
        return NULL;
    }

    // Load default CA paths
    if (X509_STORE_set_default_paths(store) != 1) {
        X509_STORE_free(store);
        X509_free(cert);
        return NULL;
    }

    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!ctx) {
        X509_STORE_free(store);
        X509_free(cert);
        return NULL;
    }

    if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(cert);
        return NULL;
    }

    if (X509_verify_cert(ctx) != 1) {
        fprintf(stderr, "X509 CA verify failed for %s: %s\n", ipAddress,
                X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        X509_free(cert);
        return NULL;
    }

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    // extract the MUD URL from the certificate
    ASN1_OBJECT *mud_oid = OBJ_txt2obj("1.3.6.1.5.5.7.1.25", 1);
    int ext_index = X509_get_ext_by_OBJ(cert, mud_oid, -1);
    ASN1_OBJECT_free(mud_oid);

    if (ext_index < 0) {
        X509_free(cert);
        fprintf(stderr, "MUD extension not found\n");
        return NULL;
    }

    X509_EXTENSION *ext = X509_get_ext(cert, ext_index);
    ASN1_OCTET_STRING *octet = X509_EXTENSION_get_data(ext);

    const unsigned char *p = ASN1_STRING_get0_data(octet);
    int len = ASN1_STRING_length(octet);

    // Decode the OCTET_STRING as ASN1_TYPE
    ASN1_TYPE *asn1 = d2i_ASN1_TYPE(NULL, &p, len);
    if (!asn1 || ASN1_TYPE_get(asn1) != V_ASN1_UTF8STRING) {
        ASN1_TYPE_free(asn1);
        X509_free(cert);
        fprintf(stderr, "Failed to decode UTF8 string from MUD extension.\n");
        return NULL;
    }

    ASN1_UTF8STRING *utf8 = asn1->value.utf8string;
    const char *raw_url = (const char *)ASN1_STRING_get0_data(utf8);
    int url_len = ASN1_STRING_length(utf8);
    const char *cleaned_url = strip_utf8_prefix(raw_url);
    char *mud_url = strndup(cleaned_url, strlen(cleaned_url));

    ASN1_TYPE_free(asn1);
    X509_free(cert);
    unlink(cert_path);

    pthread_mutex_unlock(&tmpfile_mutex);
    printf("MUD URL extracted for IP %s: %s\n", ipAddress, mud_url);
    return mud_url;


}




void apply_mud_policy_for_ip(DhcpEvent *event, const char *mud_url) {
    if (!event || !event->ipAddress || !mud_url) {
        fprintf(stderr, "Invalid parameters in apply_mud_policy_for_ip.\n");
        return;
    }

    event->mudFileURL = strdup(mud_url);  // safe copy
    event->action = NEW;

    unblock_device_traffic(event->ipAddress);
    pthread_mutex_lock(&tmpfile_mutex);
    executeOpenMudDhcpAction(event);
    pthread_mutex_unlock(&tmpfile_mutex);

    printf("Executed OpenMUD action for IP %s\n", event->ipAddress);
}



// Async processing thread
static void *process_cert_async_thread(void *arg) {
    char *ip = (char *)arg;
    printf("Async processing certificate for IP %s\n", ip);

    FILE *fp = fopen(DHCP_LOG_FILE, "r");
    if (!fp) {
        perror("fopen DHCP log");
        free(ip);
        return NULL;
    }

    char line[1024];
    DhcpEvent *event = NULL;

    while (fgets(line, sizeof(line), fp)) {
        // Check if this line is for the IP
        if (strstr(line, ip)) {
            if (event) {
                free(event->date);
                free(event->lanDevice);
                free(event->dhcpRequestFlags);
                free(event->dhcpVendor);
                free(event->macAddress);
                free(event->ipAddress);
                free(event->hostName);
                free(event->mudFileURL);
                free(event);
            }

            event = calloc(1, sizeof(DhcpEvent));

            // Parse exactly like processDhcpEventFromLog
            char *array[20] = {0};
            int i = 0;
            char *tmp = strdup(line);
            char *token = strtok(tmp, "|\t\n\r");

            while (token && i < 20) {
                array[i++] = strdup(token);
                token = strtok(NULL, "|\t\n\r");
            }

            free(tmp);

            event->action = getDhcpEventActionClass(array[1]);
            event->date = array[0];
            event->lanDevice = array[2];
            event->dhcpRequestFlags = array[4];
            event->dhcpVendor = array[7];
            event->macAddress = array[8];
            event->ipAddress = array[9];
            event->hostName = array[10];

            if (array[6] && strlen(array[6]) > 1) {
                event->mudFileURL = array[6];
            } else {
                event->mudFileURL = strdup("-");
            }

            // Clean the rest (if more than expected)
            for (int j = 11; j < i; j++) free(array[j]);
        }
    }

    fclose(fp);

    if (!event) {
        printf("No DHCP info found for IP %s\n", ip);
        free(ip);
        return NULL;
    }

    // Save the event to a file
    save_event_to_file(event);


    //  Cleanup
    free(event->date);
    free(event->lanDevice);
    free(event->dhcpRequestFlags);
    free(event->dhcpVendor);
    free(event->macAddress);
    free(event->ipAddress);
    free(event->hostName);
    if (event->mudFileURL) free(event->mudFileURL);
    free(event);
    free(ip);

    return NULL;
}


// HTTP handler
static enum MHD_Result answer_to_connection(void *cls,
    struct MHD_Connection *connection,
    const char *url,
    const char *method,
    const char *version,
    const char *upload_data,
    size_t *upload_data_size,
    void **con_cls)
{

    // === /register_mud_cert ===
    if (0 == strcmp(method, "POST") && 0 == strcmp(url, "/register_mud_cert")) {
        if (*con_cls == NULL) {
            PostContext *ctx = calloc(1, sizeof(PostContext));
            *con_cls = ctx;
            return MHD_YES;
        }

        PostContext *ctx = *con_cls;

        if (*upload_data_size != 0) {
            ctx->data = realloc(ctx->data, ctx->size + *upload_data_size);
            memcpy(ctx->data + ctx->size, upload_data, *upload_data_size);
            ctx->size += *upload_data_size;
            *upload_data_size = 0;
            return MHD_YES;
        }

        // All the data has been received
        const union MHD_ConnectionInfo *info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        if (info && info->client_addr) {
            struct sockaddr_in *addr = (struct sockaddr_in *)info->client_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);

            printf("Received certificate from %s (%zu bytes)\n", ip, ctx->size);
            save_certificate(ip, ctx->data, ctx->size);


            // Generate nonce for the IP
            char nonce[64];
            generate_nonce_for_ip(ip, nonce, sizeof(nonce));

            // Answer with the nonce
            char json_resp[128];
            snprintf(json_resp, sizeof(json_resp), "{ \"status\": \"ok\", \"nonce\": \"%s\" }", nonce);
            struct MHD_Response *response =
                MHD_create_response_from_buffer(strlen(json_resp), (void *)json_resp, MHD_RESPMEM_MUST_COPY);
            int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);

            free(ctx->data);
            free(ctx);
            *con_cls = NULL;
            return ret;
        }
    }

    // verify_nonce request
    else if (0 == strcmp(method, "POST") && 0 == strcmp(url, "/verify_nonce")) {
        if (*con_cls == NULL) {
            PostContext *ctx = calloc(1, sizeof(PostContext));
            *con_cls = ctx;
            return MHD_YES;
        }

        PostContext *ctx = *con_cls;

        if (*upload_data_size != 0) {
            ctx->data = realloc(ctx->data, ctx->size + *upload_data_size);
            memcpy(ctx->data + ctx->size, upload_data, *upload_data_size);
            ctx->size += *upload_data_size;
            *upload_data_size = 0;
            return MHD_YES;
        }

        const union MHD_ConnectionInfo *info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        if (info && info->client_addr) {
            struct sockaddr_in *addr = (struct sockaddr_in *)info->client_addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(addr->sin_addr), ip, INET_ADDRSTRLEN);

            // Save the signature to a file
            char sig_path[256];
            snprintf(sig_path, sizeof(sig_path), "/tmp/signed_nonce_%s", ip);
            pthread_mutex_lock(&tmpfile_mutex);
            FILE *f = fopen(sig_path, "w");
            if (f) {
                fwrite(ctx->data, 1, ctx->size, f);
                fclose(f);
            }
            pthread_mutex_unlock(&tmpfile_mutex);

            // Verify the signature
            if (verify_signature(ip)) {

                DhcpEvent *event = load_event_from_file(ip);
                if (event) {
                char *mud_url = verify_certificate_for_ip(ip);
            if (mud_url) {
                // send back the verification response
                const char *ok = "{ \"status\": \"verified\" }";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(ok), (void *)ok, MHD_RESPMEM_PERSISTENT);
                int ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
                MHD_destroy_response(resp);

                free(ctx->data);
                free(ctx);
                *con_cls = NULL;

                // then apply the MUD policy
                apply_mud_policy_for_ip(event, mud_url);

                free(mud_url);

                //free_dhcp_event(event);

                return ret;
            } 
            //free_dhcp_event(event);
            } else {
                const char *fail = "{ \"status\": \"invalid certificate\" }";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(fail), (void *)fail, MHD_RESPMEM_PERSISTENT);
                int ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, resp);
                MHD_destroy_response(resp);

                free(ctx->data);
                free(ctx);
                *con_cls = NULL;
                return ret;
            }
        }else {
                const char *fail = "{ \"status\": \"invalid signature\" }";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(fail), (void *)fail, MHD_RESPMEM_PERSISTENT);
                int ret = MHD_queue_response(connection, MHD_HTTP_FORBIDDEN, resp);
                MHD_destroy_response(resp);

                free(ctx->data);
                free(ctx);
                *con_cls = NULL;
                return ret;
            }
        }
    }

    // === Default fallback ===
    const char *notfound = "Not Found";
    struct MHD_Response *resp =
        MHD_create_response_from_buffer(strlen(notfound), (void *)notfound, MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, resp);
    MHD_destroy_response(resp);
    return ret;
}


// Thread function to run the HTTP server
void *x509_server_thread(void *arg) {
    printf("Starting X.509 HTTP server on port %d (/register_mud_cert)\n", X509_HTTP_PORT);

    // Flush MUD_CHAIN at startup
    int ret = system("iptables -F MUD_CHAIN");
    if (ret != 0) {
        fprintf(stderr, "Warning: could not flush MUD_CHAIN (exit code %d)\n", ret);
    } else {
        printf("Flushed MUD_CHAIN at server startup\n");
    }

    // Flush FORWARD at startup
    int ret1 = system("iptables -F FORWARD");
    if (ret1 != 0) {
        fprintf(stderr, "Warning: could not flush FORWARD (exit code %d)\n", ret1);
    } else {
        printf("Flushed FORWARD at server startup\n");
    }
    clear_all_temp_state(); // Clear any stale state

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION,
        X509_HTTP_PORT,
        NULL, NULL,
        &answer_to_connection, NULL,
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start HTTP server\n");
        return NULL;
    }

    getchar(); // Block forever unless Ctrl+C or program exit
    MHD_stop_daemon(daemon);
    return NULL;
}

// Launch server (to be called at program startup)
void start_x509_server_async() {
    mkdir("/var/state/osmud/certificates", 0755);
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, x509_server_thread, NULL);
    pthread_detach(server_thread);
}