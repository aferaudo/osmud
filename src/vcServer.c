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
#include <json-c/json.h>
#include <didkit.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <sys/time.h>
#include <curl/curl.h>


#include "dhcp_event.h"
#include "mud_manager.h"

#define VC_HTTP_PORT 8888
const char *DIDRESOLVER_CONTRACT_ADDRESS = "0xa48303B121D48b02C5FCf0f49a916860d1F61465";
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t iptables_mutex = PTHREAD_MUTEX_INITIALIZER;



// Struttura per gestire i dati POST
typedef struct {
    char *data;
    size_t size;
} PostContext;

#include <dirent.h>

typedef struct {
    char filename[128];
    volatile bool *running;
} MonitorArgs;

void *monitor_usage(void *arg) {
    MonitorArgs *args = (MonitorArgs *)arg;
    pid_t pid = getpid();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "/proc/%d/stat", pid);

    FILE *log = fopen(args->filename, "w");
    if (!log) {
        perror("Errore apertura file monitor");
        return NULL;
    }

    fprintf(log, "timestamp_ms,cpu_time_s,ram_kb\n");
    fflush(log);

    while (*(args->running)) {
        FILE *f = fopen(cmd, "r");
        if (f) {
            long unsigned utime, stime;
            char comm[256], state;
            int ppid, pgrp, session, tty_nr, tpgid;
            unsigned flags;
            long cutime, cstime, priority, nice, num_threads, itrealvalue;
            unsigned long vsize;
            long rss;
            unsigned long starttime;

            fscanf(f, "%*d %s %c %d %d %d %d %d %u "
                   "%*u %*u %*u %*u %lu %lu %ld %ld %ld %ld %ld %ld "
                   "%*ld %*llu %lu %ld",
                   comm, &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags,
                   &utime, &stime, &cutime, &cstime, &priority, &nice, &num_threads,
                   &itrealvalue, &starttime, &vsize, &rss);
            fclose(f);

            double cpu_time = (utime + stime) / (double) sysconf(_SC_CLK_TCK);
            double mem_kb = rss * (sysconf(_SC_PAGE_SIZE) / 1024.0);

            struct timeval tv;
            gettimeofday(&tv, NULL);
            long long ts_ms = (tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);

            fprintf(log, "%lld,%.3f,%.2f\n", ts_ms, cpu_time, mem_kb);
            fflush(log);
        }

        usleep(1000); // sleep for 10 ms
    }

    fclose(log);
    return NULL;
}

// Elimina tutti i file temporanei relativi ai VC
void clear_all_temp_vc_state() {
    pthread_mutex_lock(&file_mutex);
    const char *tmp_dir = "/tmp";
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
    pthread_mutex_unlock(&file_mutex);
}


// Blocca traffico IP eccetto OSMUD
void block_device_traffic_except_osmud(const char *ip) {

    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "iptables -A FORWARD -p tcp -s %s -d 192.168.10.1 --dport 8888 -j ACCEPT", ip);
    system(cmd);
    sprintf(cmd, "iptables -A FORWARD -s %s -j DROP", ip);
    system(cmd);
    printf("Blocked all traffic from %s except to OSMUD server.\n", ip);
}

// Sblocca traffico
void unblock_device_traffic(const char *ip) {
    char cmd[256];
    int i;

    // Rimuove tutte le DROP da MUD_CHAIN
    for (i = 0; i < 10; i++) {
        snprintf(cmd, sizeof(cmd), "iptables -D MUD_CHAIN -s %s -j DROP 2>/dev/null", ip);
        if (system(cmd) != 0) break;  // termina quando non trova più la regola
    }

    // Rimuove tutte le DROP da FORWARD
    for (i = 0; i < 10; i++) {
        snprintf(cmd, sizeof(cmd), "iptables -D FORWARD -s %s -j DROP 2>/dev/null", ip);
        if (system(cmd) != 0) break;
    }
    printf("Unblocked traffic for %s (MUD_CHAIN and FORWARD)\n", ip);
}

// Legge un file in memoria
static char* read_file(const char *path) {
    pthread_mutex_lock(&file_mutex);
    FILE *f = fopen(path, "r");
    if (!f) {
        pthread_mutex_unlock(&file_mutex);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc(len + 1);
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);
    pthread_mutex_unlock(&file_mutex);
    return buf;
}

// Carica evento DHCP da file
static DhcpEvent *load_event_from_file(const char *ip) {
     pthread_mutex_lock(&file_mutex);
    char path[256];
    snprintf(path, sizeof(path), "/tmp/dhcp_event_%s", ip);
    FILE *f = fopen(path, "r");
    if (!f) {
        pthread_mutex_unlock(&file_mutex);
        return NULL;
    }
    char line[1024];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return NULL; }
    fclose(f);

    DhcpEvent *event = calloc(1, sizeof(DhcpEvent));
    char *arr[9] = {0}, *tmp = strdup(line), *tok;
    int i=0;
    tok = strtok(tmp, "|\t\n\r");
    while (tok && i<8) { arr[i++] = strdup(tok); tok = strtok(NULL, "|\t\n\r"); }
    free(tmp);

    event->date             = arr[0];
    event->lanDevice        = arr[1];
    event->dhcpRequestFlags = arr[2];
    event->dhcpVendor       = arr[3];
    event->macAddress       = arr[4];
    event->ipAddress        = arr[5];
    event->mudFileURL       = strcmp(arr[6], "-")==0 ? NULL : arr[6];
    event->hostName         = strcmp(arr[7], "-")==0 ? NULL : arr[7];
    event->action           = NEW;
    pthread_mutex_unlock(&file_mutex);
    return event;
}

char *encode_verify_did_input(const char *did) {
    const char *selector = "fd8a0056";  // function selector
    const char *offset = "0000000000000000000000000000000000000000000000000000000000000020";

    size_t did_len = strlen(did);
    char length_hex[65];
    snprintf(length_hex, sizeof length_hex, "%064lx", did_len);  // lunghezza stringa in hex

    // Codifica stringa in hex
    char did_hex[1024] = {0};
    for (size_t i = 0; i < did_len; i++) {
        snprintf(did_hex + i * 2, 3, "%02x", (unsigned char)did[i]);
    }

    // Padding: riempi fino a multiplo di 32 byte
    size_t pad_len = (32 - (did_len % 32)) % 32;
    for (size_t i = 0; i < pad_len; i++) {
        strcat(did_hex, "00");
    }

    // Costruzione finale
    char *encoded = malloc(1024);
    snprintf(encoded, 1024, "0x%s%s%s%s", selector, offset, length_hex, did_hex);

    return encoded;
}

size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t real_size = size * nmemb;
    strncat((char *)userdata, (char *)ptr, real_size);
    return real_size;
}


int call_verify_did_on_ganache(const char *contract_addr, const char *did) {
    if (!contract_addr || !did) {
        fprintf(stderr, "❌ ERRORE: argomenti nulli\n");
        return -1;
    }

    printf("📡 Chiamata a call_verify_did_on_ganache\n");
    printf("   contract_addr: %s\n", contract_addr);
    printf("   did: %s\n", did);
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "❌ curl_easy_init() ha restituito NULL!\n");
        return -1;
    }

    char *data_input = encode_verify_did_input(did);

    if (!data_input) {
        fprintf(stderr, "❌ encode_verify_did_input ha restituito NULL\n");
        return -1;
    }
    printf("🔢 data_input: %s\n", data_input);

    char json[2048];
    snprintf(json, sizeof json,
        "{"
        "\"jsonrpc\":\"2.0\","
        "\"method\":\"eth_call\","
        "\"params\":[{"
        "\"to\":\"%s\","
        "\"data\":\"%s\""
        "},\"latest\"],"
        "\"id\":1"
        "}",
        contract_addr, data_input);

    struct curl_slist *headers = curl_slist_append(NULL, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_URL, "http://10.0.9.2:7545");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

    char response[2048] = {0};
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    free(data_input);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        fprintf(stderr, "CURL failed\n");
        return -1;
    }
    printf("📥 Risposta da Ganache: %s\n", response);

    // Cerca il risultato: "result":"0x01" o "0x00"
    struct json_object *resp_obj = json_tokener_parse(response);
    if (!resp_obj) {
        fprintf(stderr, " Errore nel parsing della risposta JSON\n");
        return -1;
    }

    struct json_object *result_obj;
    if (!json_object_object_get_ex(resp_obj, "result", &result_obj)) {
        fprintf(stderr, " Campo 'result' mancante nella risposta JSON\n");
        json_object_put(resp_obj);
        return -1;
    }

    const char *result_hex = json_object_get_string(result_obj);
    printf("🔍 Risultato decodificato: %s\n", result_hex);

    // Confronta se termina in '1'
    int is_true = (strcmp(result_hex, "0x1") == 0 ||
                strcmp(result_hex + strlen(result_hex) - 1, "1") == 0);

    json_object_put(resp_obj);
    return is_true ? 1 : 0;
}

char *base64url_decode(const char *input, size_t len) {
    // base64url → base64: sostituisci -/_ con +/=
    char *b64 = malloc(len + 5);
    memcpy(b64, input, len);
    b64[len] = '\0';
    for (size_t i = 0; i < len; i++) {
        if (b64[i] == '-') b64[i] = '+';
        else if (b64[i] == '_') b64[i] = '/';
    }
    // padding
    int pad = (4 - (len % 4)) % 4;
    for (int i = 0; i < pad; i++) b64[len++] = '=';
    b64[len] = '\0';

    BIO *bio, *b64b;
    char *buffer = malloc(4096);
    memset(buffer, 0, 4096);

    b64b = BIO_new(BIO_f_base64());
    BIO_set_flags(b64b, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(b64, len);
    bio = BIO_push(b64b, bio);

    int decoded_len = BIO_read(bio, buffer, 4095);
    BIO_free_all(bio);
    free(b64);

    if (decoded_len <= 0) {
        free(buffer);
        return NULL;
    }

    buffer[decoded_len] = '\0';
    return buffer;
}

bool verify_vp_jwt(const char *vp_jwt, const char *expected_challenge, double *elapsed_ganache_out) {
    char vp_options[256];
    struct timeval t_startganache, t_endganache;


    printf("Verifying VP JWT: %s\n", vp_jwt);
    printf("Expected challenge: %s\n", expected_challenge);

    snprintf(vp_options, sizeof vp_options, "{"
            "  \"proofPurpose\": \"authentication\","
            "  \"proofFormat\": \"jwt\","
            "  \"challenge\": \"%s\""
            " }",
        expected_challenge);

    const char *res = didkit_vc_verify_presentation(vp_jwt, vp_options);
    if (!res) {
        fprintf(stderr, "DIDKit error: %s\n", didkit_error_message());
        return false;
    }

    struct json_object *parsed = json_tokener_parse(res);
    if (!parsed) {
        fprintf(stderr, "Invalid JSON in verification result\n");
        return false;
    }

    struct json_object *errors;
    bool ok = false;

    if (json_object_object_get_ex(parsed, "errors", &errors) &&
        json_object_get_type(errors) == json_type_array &&
        json_object_array_length(errors) == 0) {
        ok = true;
    } else {
        fprintf(stderr, "Verification failed: %s\n", res);
        json_object_put(parsed);
        return false;
    }

    json_object_put(parsed);  // cleanup result

    char *vp_copy = strdup(vp_jwt);
    char *dot1 = strchr(vp_copy, '.');
    if (!dot1) {
        fprintf(stderr, "Invalid VP JWT format (1st dot)\n");
        free(vp_copy);
        return;
    }
    char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        fprintf(stderr, "Invalid VP JWT format (2nd dot)\n");
        free(vp_copy);
        return;
    }
    *dot2 = '\0'; // Termina payload base64
    char *vp_payload_json = base64url_decode(dot1 + 1, strlen(dot1 + 1));
    free(vp_copy);
    if (!vp_payload_json) {
        fprintf(stderr, "Base64url decoding failed\n");
        return false;
    }

    struct json_object *vp_obj = json_tokener_parse(vp_payload_json);
    free(vp_payload_json);
    if (!vp_obj) {
        fprintf(stderr, "VP payload is not valid JSON\n");
        return false;
    }

    // === Estrai issuer dalla VC contenuta
    struct json_object *vp_field;
    if (!json_object_object_get_ex(vp_obj, "vp", &vp_field)) {
        fprintf(stderr, "Missing 'vp' field in VP payload\n");
        json_object_put(vp_obj);
        return false;
    }

    struct json_object *vc_array;
    if (!json_object_object_get_ex(vp_field, "verifiableCredential", &vc_array)) {
        fprintf(stderr, "Missing verifiableCredential in VP\n");
        json_object_put(vp_obj);
        return false;
    }

    const char *vc_jwt = NULL;

    if (json_object_get_type(vc_array) == json_type_array && json_object_array_length(vc_array) > 0) {
        vc_jwt = json_object_get_string(json_object_array_get_idx(vc_array, 0));
    } else if (json_object_get_type(vc_array) == json_type_string) {
        // In alcuni casi verifiableCredential è una singola stringa JWT
        vc_jwt = json_object_get_string(vc_array);
    } else {
        fprintf(stderr, " Unexpected verifiableCredential format (not array or string)\n");
        json_object_put(vp_obj);
        return false;
    }
    json_object_put(vp_obj); // libera memoria VP

    if (!vc_jwt) {
        fprintf(stderr, "Failed to extract VC JWT\n");
        return;
    }

    // === 3. Estrai payload VC JWT ===
    char *vc_copy = strdup(vc_jwt);
    char *vcdot1 = strchr(vc_copy, '.');
    if (!vcdot1) {
        fprintf(stderr, "Invalid VC JWT format (1st dot)\n");
        free(vc_copy);
        return;
    }
    char *vcdot2 = strchr(vcdot1 + 1, '.');
    if (!vcdot2) {
        fprintf(stderr, "Invalid VC JWT format (2nd dot)\n");
        free(vc_copy);
        return;
    }
    *vcdot2 = '\0';
    char *vc_payload_json = base64url_decode(vcdot1 + 1, strlen(vcdot1 + 1));
    free(vc_copy);
    if (!vc_payload_json) {
        fprintf(stderr, "Failed to decode VC payload\n");
        return;
    }

    struct json_object *vc_payload_obj = json_tokener_parse(vc_payload_json);
    free(vc_payload_json);
    if (!vc_payload_obj) {
        fprintf(stderr, "Malformed VC JSON\n");
        return;
    }

    // === 4. Estrai campo "vc" interno ===
    struct json_object *vc_obj;
    if (!json_object_object_get_ex(vc_payload_obj, "vc", &vc_obj)) {
        fprintf(stderr, "Missing 'vc' field in VC payload\n");
        json_object_put(vc_payload_obj);
        return;
    }

    // === 5. Estrai mudURL ===
    struct json_object *issuer_obj;
    if (!json_object_object_get_ex(vc_obj, "issuer", &issuer_obj)) {
        fprintf(stderr, "Missing issuer in VC\n");
        json_object_put(vc_payload_obj);
        return;
    }

    const char *issuer_did = json_object_get_string(issuer_obj);


    printf(" Issuer estratto: %s\n", issuer_did);

    gettimeofday(&t_startganache, NULL);
    // === Verifica DID su contratto Ethereum
    int trusted = call_verify_did_on_ganache(DIDRESOLVER_CONTRACT_ADDRESS, issuer_did);
    if (trusted != 1) {
        fprintf(stderr, " Issuer non è autorizzato nel contratto\n");
        return false;
    }
    gettimeofday(&t_endganache, NULL);

    double elapsed_ganache = 
    (t_endganache.tv_sec - t_startganache.tv_sec) * 1000.0 +
    (t_endganache.tv_usec - t_startganache.tv_usec) / 1000.0;

    printf(" Verifica DID su contratto Ethereum completata in %.2f millisecondi\n", elapsed_ganache);

    *elapsed_ganache_out = elapsed_ganache / 1000.0; // Converti in secondi

    printf(" Issuer è autorizzato nel contratto\n");
    return true;
}


void process_verified_vp_for_ip(const char *ip, const char *vp_jwt) {
    // === 1. Estrai payload della VP JWT ===
    char *vp_copy = strdup(vp_jwt);
    char *dot1 = strchr(vp_copy, '.');
    if (!dot1) {
        fprintf(stderr, "Invalid VP JWT format (1st dot)\n");
        free(vp_copy);
        return;
    }
    char *dot2 = strchr(dot1 + 1, '.');
    if (!dot2) {
        fprintf(stderr, "Invalid VP JWT format (2nd dot)\n");
        free(vp_copy);
        return;
    }
    *dot2 = '\0'; // Termina payload base64
    char *vp_payload_json = base64url_decode(dot1 + 1, strlen(dot1 + 1));
    free(vp_copy);
    if (!vp_payload_json) {
        fprintf(stderr, "Failed to decode VP payload\n");
        return;
    }

    struct json_object *vp_obj = json_tokener_parse(vp_payload_json);
    free(vp_payload_json);
    if (!vp_obj) {
        fprintf(stderr, "Malformed VP JSON\n");
        return;
    }

    // === 2. Estrai la VC JWT (assunta unica) ===
    struct json_object *vp_field;
    if (!json_object_object_get_ex(vp_obj, "vp", &vp_field)) {
        fprintf(stderr, "Missing 'vp' field in VP payload\n");
        json_object_put(vp_obj);
        return;
    }

    struct json_object *vc_arr;
    if (!json_object_object_get_ex(vp_field, "verifiableCredential", &vc_arr)) {
        fprintf(stderr, "Missing verifiableCredential in VP\n");
        json_object_put(vp_obj);
        return;
    }

    const char *vc_jwt = NULL;
    if (json_object_get_type(vc_arr) == json_type_array && json_object_array_length(vc_arr) > 0) {
        vc_jwt = json_object_get_string(json_object_array_get_idx(vc_arr, 0));
    } else if (json_object_get_type(vc_arr) == json_type_string) {
        vc_jwt = json_object_get_string(vc_arr);
    } else {
        fprintf(stderr, "Unexpected verifiableCredential format\n");
        json_object_put(vp_obj);
        return;
    }

    json_object_put(vp_obj); // libera memoria VP

    if (!vc_jwt) {
        fprintf(stderr, "Failed to extract VC JWT\n");
        return;
    }

    // === 3. Estrai payload VC JWT ===
    char *vc_copy = strdup(vc_jwt);
    char *vcdot1 = strchr(vc_copy, '.');
    if (!vcdot1) {
        fprintf(stderr, "Invalid VC JWT format (1st dot)\n");
        free(vc_copy);
        return;
    }
    char *vcdot2 = strchr(vcdot1 + 1, '.');
    if (!vcdot2) {
        fprintf(stderr, "Invalid VC JWT format (2nd dot)\n");
        free(vc_copy);
        return;
    }
    *vcdot2 = '\0';
    char *vc_payload_json = base64url_decode(vcdot1 + 1, strlen(vcdot1 + 1));
    free(vc_copy);
    if (!vc_payload_json) {
        fprintf(stderr, "Failed to decode VC payload\n");
        return;
    }

    struct json_object *vc_payload_obj = json_tokener_parse(vc_payload_json);
    free(vc_payload_json);
    if (!vc_payload_obj) {
        fprintf(stderr, "Malformed VC JSON\n");
        return;
    }

    // === 4. Estrai campo "vc" interno ===
    struct json_object *vc_obj;
    if (!json_object_object_get_ex(vc_payload_obj, "vc", &vc_obj)) {
        fprintf(stderr, "Missing 'vc' field in VC payload\n");
        json_object_put(vc_payload_obj);
        return;
    }

    // === 5. Estrai mudURL ===
    struct json_object *cs_obj;
    if (!json_object_object_get_ex(vc_obj, "credentialSubject", &cs_obj)) {
        fprintf(stderr, "Missing credentialSubject in VC\n");
        json_object_put(vc_payload_obj);
        return;
    }

    struct json_object *mudurl_obj;
    if (!json_object_object_get_ex(cs_obj, "mudURL", &mudurl_obj)) {
        fprintf(stderr, "Missing mudURL in credentialSubject\n");
        json_object_put(vc_payload_obj);
        return;
    }

    const char *mudurl = json_object_get_string(mudurl_obj);
    printf(" Extracted mudURL: %s\n", mudurl);

    // === 6. Applica il MUD al dispositivo ===
    DhcpEvent *event = load_event_from_file(ip);
    if (!event) {
        fprintf(stderr, "Missing DHCP event for IP %s\n", ip);
        json_object_put(vc_payload_obj);
        return;
    }

    if (event->mudFileURL) free(event->mudFileURL);
    event->mudFileURL = strdup(mudurl);

	unblock_device_traffic(event->ipAddress);
    pthread_mutex_lock(&iptables_mutex);
    executeOpenMudDhcpAction(event);
    pthread_mutex_unlock(&iptables_mutex);
    free_dhcp_event(event);
    json_object_put(vc_payload_obj);
}



// Genera e salva un nonce per IP
static void generate_nonce_for_ip(const char *ip, char *nonce_out, size_t size) {
    srand(time(NULL) ^ getpid());
    snprintf(nonce_out, size, "%08x%08x", rand(), rand());
    char nonce_path[256];
    snprintf(nonce_path, sizeof(nonce_path), "/tmp/nonce_%s", ip);
    //pthread_mutex_lock(&file_mutex);
    FILE *f = fopen(nonce_path, "w");
    if (f) {
        fprintf(f, "%s", nonce_out);
        fclose(f);
    }
    //pthread_mutex_unlock(&file_mutex);
}

// Libera evento DHCP
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

// Salva evento DHCP su file
void save_event_to_file(const DhcpEvent *event) {
    pthread_mutex_lock(&file_mutex);
    char path[256];
    snprintf(path, sizeof(path), "/tmp/dhcp_event_%s", event->ipAddress);
    char new_content[1024];
    snprintf(new_content, sizeof(new_content),
        "%s|%s|%s|%s|%s|%s|%s|%s\n",
        event->date, event->lanDevice, event->dhcpRequestFlags,
        event->dhcpVendor, event->macAddress, event->ipAddress,
        event->mudFileURL ? event->mudFileURL : "-",
        event->hostName  ? event->hostName  : "-");

    bool is_new_ip = true;
    FILE *existing = fopen(path, "r");
    if (existing) {
        char buf[1024];
        if (fgets(buf, sizeof(buf), existing)) {
            // verifica IP
            char *cp = strdup(buf), *tok = strtok(cp, "|\t\n\r");
            for (int i=1; tok && i<6; ++i) tok = strtok(NULL, "|\t\n\r");
            if (tok && strcmp(tok, event->ipAddress)==0) is_new_ip = false;
            free(cp);
        }
        fclose(existing);
    }
    if (!is_new_ip) {
        printf("Evento per IP %s già presente, non sovrascritto.\n", event->ipAddress);
        return;
    }       
    
    if (is_new_ip) {
        // Blocca traffico del device eccetto OSMUD
        block_device_traffic_except_osmud(event->ipAddress);
    }

    FILE *f2 = fopen(path, "w");
    if (!f2) { perror("fopen event save"); return; }
    fputs(new_content, f2);
    fclose(f2);
    printf("Evento saved for IP %s\n", event->ipAddress);

    pthread_mutex_unlock(&file_mutex);
}


static enum MHD_Result answer_to_connection(void *cls,
    struct MHD_Connection *connection,
    const char *url, const char *method, const char *version,
    const char *upload_data, size_t *upload_data_size, void **con_cls) {

    if (*con_cls == NULL) {
        PostContext *ctx = calloc(1, sizeof(PostContext));
        *con_cls = ctx;
        return MHD_YES;
    }
    PostContext *ctx = *con_cls;

    if (*upload_data_size > 0) {
        ctx->data = realloc(ctx->data, ctx->size + *upload_data_size);
        memcpy(ctx->data + ctx->size, upload_data, *upload_data_size);
        ctx->size += *upload_data_size;
        *upload_data_size = 0;

        ctx->data = realloc(ctx->data, ctx->size + 1);
        ctx->data[ctx->size] = '\0';
        return MHD_YES;
    }

    struct timeval t_startauth, t_endauth, t_startrules, t_endrules;

    // === Recupero IP dal header HTTP oppure da socket ===
    char ip[64] = {0};
    const char *ip_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Forwarded-For");
    if (!ip_header)
        ip_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "X-Real-IP");

    if (ip_header && strlen(ip_header) < sizeof(ip)) {
        strncpy(ip, ip_header, sizeof(ip) - 1);
        printf("[INFO] IP from header: %s\n", ip);
    } else {
        const union MHD_ConnectionInfo *ci = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
        struct sockaddr_in *addr = (struct sockaddr_in*)ci->client_addr;
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        printf("[INFO] IP from socket: %s\n", ip);
    }

    // === 1) CHALLENGE REQUEST ===
    if (strcmp(url, "/challenge") == 0 && strcmp(method, "GET") == 0) {
        char nonce[64];
        generate_nonce_for_ip(ip, nonce, sizeof(nonce));

        char response[128];
        snprintf(response, sizeof(response), "{ \"challenge\": \"%s\" }", nonce);
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(response), (void*)response, MHD_RESPMEM_MUST_COPY);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        free(ctx); *con_cls = NULL;
        return ret;
    }

    // === 2) SUBMIT VP ===
    if (strcmp(url, "/submit_vp") == 0 && strcmp(method, "POST") == 0) {
        printf("[INFO] Ricevuta POST /submit_vp da IP %s\n", ip);
        char path_nonce[256];
        snprintf(path_nonce, sizeof(path_nonce), "/tmp/nonce_%s", ip);
        char *expected_nonce = read_file(path_nonce);
        if (!expected_nonce) {
            const char *err = "Missing challenge";
            struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(err), (void*)err, MHD_RESPMEM_PERSISTENT);
            int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, resp);
            MHD_destroy_response(resp);
            free(ctx->data); free(ctx); *con_cls = NULL;
            return ret;
        }
        
        double elapsed_ganache = 0.0;

        pthread_t monitor_thread;
        volatile bool monitor_running = true;
        MonitorArgs args;

        // Crea nome file CSV per questa connessione
        snprintf(args.filename, sizeof(args.filename), "monitor_%s.csv", ip);
        args.running = &monitor_running;

        // Avvia thread di monitoraggio
        pthread_create(&monitor_thread, NULL, monitor_usage, &args);

        gettimeofday(&t_startauth, NULL);

        bool ok = verify_vp_jwt(ctx->data, expected_nonce, &elapsed_ganache);

        gettimeofday(&t_endauth, NULL);
        monitor_running = false;
        pthread_join(monitor_thread, NULL);
        free(expected_nonce);

        const char *msg = ok ? "{ \"status\":\"verified\" }" : "{ \"status\":\"invalid\" }";
        struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
        int ret = MHD_queue_response(connection, ok ? MHD_HTTP_OK : MHD_HTTP_FORBIDDEN, resp);
        MHD_destroy_response(resp);

        if (ok) {
            gettimeofday(&t_startrules, NULL);
            process_verified_vp_for_ip(ip, ctx->data);  
            gettimeofday(&t_endrules, NULL);
        }

        double elapsed = (t_endauth.tv_sec - t_startauth.tv_sec) + 
                         (t_endauth.tv_usec - t_startauth.tv_usec) / 1e6;
        printf("[INFO] Total authentication time: %.3f seconds\n", elapsed);

        
        double elapsed_rules = (t_endrules.tv_sec - t_startrules.tv_sec) +
                                (t_endrules.tv_usec - t_startrules.tv_usec) / 1e6;
        printf("[INFO] Time for rule application: %.3f seconds\n", elapsed_rules);

        double elapsed_ver = elapsed-elapsed_ganache;
        

        // Scrivi su CSV
        FILE *logf = fopen("ruletime10.csv", "a");
        if (logf) {
            fprintf(logf, "%s,%.6f,%.6f,%.6f,%.6f\n", ip, elapsed, elapsed_ver, elapsed_ganache, elapsed_rules);
            fclose(logf);
        } else {
            fprintf(stderr, "⚠️  Impossibile scrivere su ruletime.csv\n");
        }

        free(ctx->data); free(ctx); *con_cls = NULL;
        return ret;
    }

    // Default 404
    const char *msg = "Not Found";
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
    int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, resp);
    MHD_destroy_response(resp);
    free(ctx->data); free(ctx); *con_cls = NULL;
    return ret;
}


// === Server thread entrypoint ===
void *vc_server_thread(void *arg) {
    printf("Starting VC HTTP server on port %d (/challenge, /submit_vp)\n", VC_HTTP_PORT);
     clear_all_temp_vc_state();
    system("iptables -F MUD_CHAIN");
    system("iptables -F FORWARD");
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "curl_global_init() failed\n");
        return 1;
    }
    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_THREAD_PER_CONNECTION, VC_HTTP_PORT, NULL,NULL,
        &answer_to_connection, NULL, MHD_OPTION_END);
    if (!daemon) {
        fprintf(stderr,"Failed to start HTTP server\n");
        return NULL;
    }
    getchar();  // block
    MHD_stop_daemon(daemon);
    return NULL;
}

// === Launch server at startup ===
void start_vc_server_async() {
    mkdir("/var/state/osmud/certificates",0755);
    pthread_t thr;
    pthread_create(&thr,NULL,vc_server_thread,NULL);
    pthread_detach(thr);
}
