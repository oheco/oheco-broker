#define _POSIX_C_SOURCE 200809L
#include "ob_api_internal.h"
#include "ob_json.h"

#include <arpa/inet.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_init_result = CURLE_FAILED_INIT;
static void initialize_curl(void) { curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT); }

/* curl 8.22.0 installs its ambient keylog callback before this application
 * callback, but creates SSL/traffic secrets only afterwards. Clear it on each
 * private context without mutating process-global environment or TLS settings.
 * Upstream curl global initialization may still open/create an empty keylog.
 * This guarantee is for SDK requests, not unrelated caller-owned TLS handles. */
CURLcode ob_api_secure_ssl_context(CURL *easy, void *context, void *user) {
    (void)easy; (void)user;
    if (!context) return CURLE_SSL_CONNECT_ERROR;
    SSL_CTX_set_keylog_callback((SSL_CTX *)context, NULL);
    return CURLE_OK;
}

static int fail(ob_api_error *e, int code, const char *message) {
    if (e) { e->code = code; snprintf(e->message, sizeof(e->message), "%s", message); }
    return code;
}
static void reset(ob_api_error *e, char **out) {
    if (e) memset(e, 0, sizeof(*e));
    if (out) *out = NULL;
}
static void erase(void *p, size_t n) {
    volatile unsigned char *q = p;
    while (n--) *q++ = 0;
}
static void wipe_json(cJSON *j) {
    for (; j; j = j->next) {
        if (j->valuestring) erase(j->valuestring, strlen(j->valuestring));
        if (j->child) wipe_json(j->child);
    }
}
static void delete_json(cJSON *j) { wipe_json(j); cJSON_Delete(j); }
static void secret_free(char *s) { if (s) { erase(s, strlen(s)); free(s); } }
void ob_api_response_free(char *s) { secret_free(s); }
void ob_api_credentials_clear(ob_api_credentials *c) { if (c) erase(c, sizeof(*c)); }

static int token_valid(const char *s) {
    if (!s) return 1;
    size_t n = strnlen(s, 8193);
    if (n > 8192) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || strchr("._~+/-=", c))) return 0;
    }
    return 1;
}
static int id_valid(const char *s) {
    if (!s) return 0;
    size_t n = strnlen(s, 129);
    if (!n || n > 128) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    return 1;
}
static int path_valid(const char *s) {
    if (!s || strncmp(s, "/v1/", 4) || strnlen(s, 2049) > 2048) return 0;
    const char *query = strchr(s, '?');
    size_t path_len = query ? (size_t)(query - s) : strlen(s);
    if (path_len <= 4 || s[path_len - 1] == '/') return 0;
    for (size_t i = 0; i < path_len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || strchr("/_-.", c))) return 0;
        if (c == '/' && i + 1 < path_len && s[i + 1] == '/') return 0;
    }
    const char *segment = s + 1;
    while (segment < s + path_len) {
        const char *end = memchr(segment, '/', (size_t)(s + path_len - segment));
        if (!end) end = s + path_len;
        size_t n = (size_t)(end - segment);
        if ((n == 1 && segment[0] == '.') || (n == 2 && !memcmp(segment, "..", 2))) return 0;
        segment = end + 1;
    }
    if (query) {
        if (!query[1]) return 0;
        for (const char *p = query + 1; *p; p++) {
            unsigned char c = (unsigned char)*p;
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || strchr("_-=&", c))) return 0;
        }
    }
    return 1;
}

static int loopback_host(const char *host) {
    struct in_addr ip4;
    struct in6_addr ip6;
    if (!strcmp(host, "localhost")) return 1;
    if (inet_pton(AF_INET, host, &ip4) == 1)
        return (ntohl(ip4.s_addr) >> 24) == 127;
    if (!strcmp(host, "[::1]")) return 1;
    return inet_pton(AF_INET6, host, &ip6) == 1 && IN6_IS_ADDR_LOOPBACK(&ip6);
}

ob_api_client *ob_api_client_create(const ob_api_options *o, ob_api_error *e) {
    reset(e, NULL);
    if (!o || !o->base_url || !*o->base_url || strnlen(o->base_url, 2049) > 2048 ||
        !token_valid(o->tenant_token) || o->timeout_ms < 0 || o->timeout_ms > 300000) {
        fail(e, OB_API_INVALID, "Invalid client options"); return NULL;
    }
    if (pthread_once(&curl_once, initialize_curl) || curl_init_result != CURLE_OK) {
        fail(e, OB_API_TRANSPORT, "HTTP library initialization failed"); return NULL;
    }
    CURLU *u = curl_url();
    char *scheme = NULL, *host = NULL, *path = NULL, *port = NULL, *part = NULL;
    ob_api_client *c = NULL;
    if (!u) { fail(e, OB_API_NOMEM, "Allocation failed"); return NULL; }
    if (curl_url_set(u, CURLUPART_URL, o->base_url, 0) != CURLUE_OK ||
        curl_url_get(u, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
        curl_url_get(u, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
        curl_url_get(u, CURLUPART_PATH, &path, 0) != CURLUE_OK ||
        (strcmp(scheme, "https") && strcmp(scheme, "http")) || strcmp(path, "/")) goto invalid;
    const CURLUPart forbidden[] = {CURLUPART_USER, CURLUPART_PASSWORD, CURLUPART_OPTIONS,
                                  CURLUPART_QUERY, CURLUPART_FRAGMENT, CURLUPART_ZONEID};
    for (size_t i = 0; i < sizeof(forbidden)/sizeof(forbidden[0]); i++) {
        if (curl_url_get(u, forbidden[i], &part, 0) == CURLUE_OK) goto invalid;
        curl_free(part); part = NULL;
    }
    /* Reject non-ASCII hostnames; URL credentials/paths are not silently discarded. */
    for (const unsigned char *p = (const unsigned char *)host; *p; p++)
        if (*p <= 32 || *p >= 127 || *p == '%' || *p == '\\') goto invalid;
    if (!strcmp(scheme, "http") && !loopback_host(host)) goto invalid;
    c = calloc(1, sizeof(*c));
    if (!c) goto nomem;
    /* Keep the validated curl-normalized origin, never caller's raw spelling. */
    if (curl_url_get(u, CURLUPART_URL, &part, 0) != CURLUE_OK) goto nomem;
    size_t len = strlen(part);
    while (len && part[len - 1] == '/') len--;
    c->base_url = malloc(len + 1);
    if (!c->base_url) goto nomem;
    memcpy(c->base_url, part, len); c->base_url[len] = 0;
    curl_free(part); part = NULL;
    if (o->tenant_token && !(c->tenant_token = strdup(o->tenant_token))) goto nomem;
    if (o->ca_file && !(c->ca_file = strdup(o->ca_file))) goto nomem;
    c->timeout_ms = o->timeout_ms ? o->timeout_ms : 15000;
    if (!strcmp(scheme, "http") && !strcmp(host, "localhost")) {
        if (curl_url_get(u, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) != CURLUE_OK) goto invalid;
        c->localhost_resolve = malloc(strlen(port) + 32);
        if (!c->localhost_resolve) goto nomem;
        sprintf(c->localhost_resolve, "localhost:%s:127.0.0.1", port);
    }
    goto done;
invalid:
    fail(e, OB_API_INVALID, "Expected HTTPS origin or literal loopback HTTP origin");
    ob_api_client_destroy(c); c = NULL; goto done;
nomem:
    fail(e, OB_API_NOMEM, "Allocation failed"); ob_api_client_destroy(c); c = NULL;
done:
    curl_free(scheme); curl_free(host); curl_free(path); curl_free(port); curl_free(part);
    curl_url_cleanup(u); return c;
}
void ob_api_client_destroy(ob_api_client *c) {
    if (!c) return;
    ob_auth_manager_destroy(c->auth);
    free(c->base_url); secret_free(c->tenant_token); free(c->ca_file);
    free(c->localhost_resolve); erase(c, sizeof(*c)); free(c);
}

static cJSON *parse_json(const char *s, size_t n) {
    return ob_json_parse_complete(s, n);
}
static int contains_hash(const cJSON *j) {
    for (; j; j = j->next) {
        if (j->string && (!strcmp(j->string, "password_hash") ||
            !strcmp(j->string, "passwordHash") || !strcmp(j->string, "hashed_password"))) return 1;
        if (j->child && contains_hash(j->child)) return 1;
    }
    return 0;
}
struct buffer { char *data; size_t used, capacity, headers; int limit, nomem; };
static size_t body_write(char *ptr, size_t size, size_t count, void *arg) {
    struct buffer *b = arg;
    if (count && size > SIZE_MAX/count) { b->limit = 1; return 0; }
    size_t n = size * count;
    if (n > OB_API_MAX_RESPONSE_BYTES - b->used) { b->limit = 1; return 0; }
    size_t wanted = b->used + n + 1;
    if (wanted > b->capacity) {
        size_t cap = b->capacity ? b->capacity : 1024;
        while (cap < wanted && cap < OB_API_MAX_RESPONSE_BYTES + 1u) cap *= 2;
        if (cap > OB_API_MAX_RESPONSE_BYTES + 1u) cap = OB_API_MAX_RESPONSE_BYTES + 1u;
        char *p = realloc(b->data, cap);
        if (!p) { b->nomem = 1; return 0; }
        b->data = p; b->capacity = cap;
    }
    if (n) memcpy(b->data + b->used, ptr, n);
    b->used += n; b->data[b->used] = 0; return n;
}
static size_t header_write(char *ptr, size_t size, size_t count, void *arg) {
    (void)ptr;
    struct buffer *b = arg;
    if (count && size > SIZE_MAX/count) { b->limit = 1; return 0; }
    size_t n = size * count;
    if (n > OB_API_MAX_HEADER_BYTES - b->headers) { b->limit = 1; return 0; }
    b->headers += n; return n;
}

struct request_cancel { ob_api_cancel_callback callback; void *user; };
static int request_progress(void *arg, curl_off_t download_total, curl_off_t downloaded,
                             curl_off_t upload_total, curl_off_t uploaded) {
    (void)download_total; (void)downloaded; (void)upload_total; (void)uploaded;
    struct request_cancel *cancel = arg;
    return cancel->callback ? cancel->callback(cancel->user) : 0;
}
static int request_raw(ob_api_client *c, const char *method, const char *path,
                    const char *bearer, const char *body, char **out, ob_api_error *e,
                    ob_api_cancel_callback callback, void *user) {
    struct request_cancel cancel = {callback, user};
    reset(e, out);
    if (!c || !out || !method || (strcmp(method,"GET") && strcmp(method,"POST") &&
        strcmp(method,"PATCH") && strcmp(method,"DELETE")) || !path_valid(path) ||
        (body && !strcmp(method, "GET"))) return fail(e, OB_API_INVALID, "Invalid request arguments");
    const char *token = bearer ? bearer : c->tenant_token;
    if (!token_valid(token)) return fail(e, OB_API_INVALID, "Invalid bearer token");
    size_t body_len = body ? strnlen(body, OB_API_MAX_REQUEST_BYTES + 1u) : 0;
    if (body_len > OB_API_MAX_REQUEST_BYTES) return fail(e, OB_API_LIMIT, "Request body limit exceeded");
    if (body) {
        cJSON *j = parse_json(body, body_len);
        if (!j) return fail(e, OB_API_JSON, "Invalid request JSON");
        delete_json(j);
    }
    CURL *easy = curl_easy_init();
    struct curl_slist *headers = NULL, *resolve = NULL;
    struct buffer b = {0};
    char *url = NULL, *authorization = NULL;
    CURLcode cr = CURLE_OK;
    int result = OB_API_OK;
    long status = 0;
    if (!easy) return fail(e, OB_API_NOMEM, "Allocation failed");
    url = malloc(strlen(c->base_url) + strlen(path) + 1);
    if (!url) goto nomem;
    sprintf(url, "%s%s", c->base_url, path);
#define ADD_HEADER(value) do { struct curl_slist *tmp = curl_slist_append(headers, (value)); \
    if (!tmp) { goto nomem; } headers = tmp; } while (0)
    ADD_HEADER("Accept: application/json");
    ADD_HEADER("Content-Type: application/json");
    ADD_HEADER("Expect:");
    if (token && *token) {
        authorization = malloc(strlen(token) + 23);
        if (!authorization) goto nomem;
        sprintf(authorization, "Authorization: Bearer %s", token); ADD_HEADER(authorization);
    }
    if (c->localhost_resolve) {
        resolve = curl_slist_append(NULL, c->localhost_resolve);
        if (!resolve) goto nomem;
    }
#define SETOPT(option,value) do { cr = curl_easy_setopt(easy, (option), (value)); \
    if (cr != CURLE_OK) goto transport; } while (0)
    SETOPT(CURLOPT_URL, url);
    SETOPT(CURLOPT_CUSTOMREQUEST, method);
    SETOPT(CURLOPT_HTTPHEADER, headers);
    SETOPT(CURLOPT_NOSIGNAL, 1L);
    if (callback) {
        SETOPT(CURLOPT_NOPROGRESS, 0L);
        SETOPT(CURLOPT_XFERINFOFUNCTION, request_progress);
        SETOPT(CURLOPT_XFERINFODATA, &cancel);
    }
    SETOPT(CURLOPT_TIMEOUT_MS, c->timeout_ms);
    SETOPT(CURLOPT_CONNECTTIMEOUT_MS, c->timeout_ms < 5000 ? c->timeout_ms : 5000L);
    SETOPT(CURLOPT_LOW_SPEED_LIMIT, 1L);
    SETOPT(CURLOPT_LOW_SPEED_TIME, 10L);
    SETOPT(CURLOPT_FOLLOWLOCATION, 0L);
    SETOPT(CURLOPT_MAXREDIRS, 0L);
    SETOPT(CURLOPT_PROTOCOLS_STR, "http,https");
    SETOPT(CURLOPT_REDIR_PROTOCOLS_STR, "https");
    SETOPT(CURLOPT_PROXY, "");
    SETOPT(CURLOPT_SSL_VERIFYPEER, 1L);
    SETOPT(CURLOPT_SSL_VERIFYHOST, 2L);
    SETOPT(CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);
    SETOPT(CURLOPT_SSL_CTX_FUNCTION, ob_api_secure_ssl_context);
    SETOPT(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
    SETOPT(CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)OB_API_MAX_RESPONSE_BYTES);
    SETOPT(CURLOPT_WRITEFUNCTION, body_write);
    SETOPT(CURLOPT_WRITEDATA, &b);
    SETOPT(CURLOPT_HEADERFUNCTION, header_write);
    SETOPT(CURLOPT_HEADERDATA, &b);
    if (c->ca_file) SETOPT(CURLOPT_CAINFO, c->ca_file);
    if (resolve) SETOPT(CURLOPT_RESOLVE, resolve);
    if (body) {
        SETOPT(CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)body_len);
        SETOPT(CURLOPT_POSTFIELDS, body);
    }
    cr = curl_easy_perform(easy);
    curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &status);
    if (e) e->http_status = status;
    if (b.limit || cr == CURLE_FILESIZE_EXCEEDED) { result = fail(e, OB_API_LIMIT, "Response budget exceeded"); goto done; }
    if (b.nomem) goto nomem;
    if (cr != CURLE_OK) goto transport;
    if (b.used) {
        if (memchr(b.data, 0, b.used)) { result = fail(e, OB_API_JSON, "Invalid response JSON"); goto done; }
        cJSON *j = parse_json(b.data, b.used);
        if (!j) { result = fail(e, OB_API_JSON, "Invalid response JSON"); goto done; }
        int hash = contains_hash(j); delete_json(j);
        if (hash) { result = fail(e, OB_API_JSON, "Unsafe response fields rejected"); goto done; }
    } else {
        if (!b.data) b.data = calloc(1, 1);
        if (!b.data) goto nomem;
    }
    *out = b.data; b.data = NULL;
    if (status < 200 || status >= 300) result = fail(e, OB_API_HTTP, "Control server returned an HTTP error");
    goto done;
nomem:
    result = fail(e, OB_API_NOMEM, "Allocation failed"); goto done;
transport:
    if (e) e->transport_code = (int)cr;
    result = fail(e, OB_API_TRANSPORT, "HTTP transport or TLS verification failed");
done:
    if (b.data) { erase(b.data, b.used); free(b.data); }
    for (struct curl_slist *h = headers; h; h = h->next) if (h->data) erase(h->data, strlen(h->data));
    curl_slist_free_all(headers); curl_slist_free_all(resolve);
    secret_free(authorization); free(url); curl_easy_cleanup(easy);
    return result;
#undef SETOPT
#undef ADD_HEADER
}

int ob_api_request_cancelled(ob_api_client *c, const char *method, const char *path,
                    const char *bearer, const char *body, char **out, ob_api_error *e,
                    ob_api_cancel_callback callback, void *user) {
    char account_token[65] = {0};
    if (c && c->auth && !bearer) {
        reset(e, out);
        int rc = ob_auth_account_bearer(c->auth, account_token, e, callback, user);
        if (rc) { erase(account_token, sizeof(account_token)); return rc; }
        bearer = account_token;
    }
    int rc = request_raw(c, method, path, bearer, body, out, e, callback, user);
    /* GET is idempotent. A refresh may recover an access credential superseded
     * by another process; NEVER replay an arbitrary mutation or scoped bearer. */
    if (c && c->auth && bearer == account_token && method && !strcmp(method, "GET")
        && rc == OB_API_HTTP && e && e->http_status == 401) {
        ob_api_error refresh_error = {0};
        ob_auth_credentials current = {0};
        ob_auth_manager_snapshot(c->auth, &current, &refresh_error);
        int refresh_result = strcmp(current.token, account_token) ? 0 :
            ob_auth_manager_refresh_cancelled(c->auth, 1, &refresh_error, callback, user);
        ob_auth_credentials_clear(&current);
        if (!refresh_result &&
            !ob_auth_account_bearer(c->auth, account_token, &refresh_error, callback, user)) {
            ob_api_response_free(out ? *out : NULL);
            if (out) *out = NULL;
            rc = request_raw(c, method, path, account_token, body, out, e, callback, user);
        }
    }
    erase(account_token, sizeof(account_token));
    return rc;
}

int ob_api_request(ob_api_client *c, const char *method, const char *path,
                    const char *bearer, const char *body, char **out, ob_api_error *e) {
    return ob_api_request_cancelled(c, method, path, bearer, body, out, e, NULL, NULL);
}
static int bad_args(char **out, ob_api_error *e) {
    reset(e, out); return fail(e, OB_API_INVALID, "Invalid typed request arguments");
}
static int text_valid(const char *s, size_t max, int allow_empty) {
    if (!s) return 0;
    size_t n = strnlen(s, max + 1);
    return n <= max && (allow_empty || n > 0);
}
static int send_object(ob_api_client *c, const char *method, const char *path,
                       const char *token, cJSON *j, char **out, ob_api_error *e) {
    if (!j) { reset(e, out); return fail(e, OB_API_NOMEM, "Allocation failed"); }
    char *body = cJSON_PrintUnformatted(j);
    delete_json(j);
    if (!body) { reset(e, out); return fail(e, OB_API_NOMEM, "Allocation failed"); }
    int rc = ob_api_request(c, method, path, token, body, out, e);
    erase(body, strlen(body)); cJSON_free(body); return rc;
}
static cJSON *one_string(const char *key, const char *value) {
    cJSON *j = cJSON_CreateObject();
    if (j && !cJSON_AddStringToObject(j, key, value)) { delete_json(j); j = NULL; }
    return j;
}
static int route(char *path, size_t size, const char *kind, const char *id, const char *suffix) {
    if (!id_valid(id)) return 0;
    int n = snprintf(path, size, "/v1/%s/%s%s", kind, id, suffix);
    return n > 0 && (size_t)n < size;
}

int ob_api_credentials_generate(ob_api_credentials *creds, ob_api_error *e) {
    reset(e, NULL);
    if (!creds) return fail(e, OB_API_INVALID, "Invalid credential output");
    ob_api_credentials_clear(creds);
    unsigned char random[32];
    if (RAND_bytes(random, sizeof(random)) != 1) {
        erase(random, sizeof(random)); return fail(e, OB_API_CRYPTO, "Secure random generation failed");
    }
    random[6] = (random[6] & 15) | 64; random[8] = (random[8] & 63) | 128;
    snprintf(creds->name, sizeof(creds->name),
             "tenant-%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             random[0],random[1],random[2],random[3],random[4],random[5],random[6],random[7],
             random[8],random[9],random[10],random[11],random[12],random[13],random[14],random[15]);
    for (size_t i=0; i<16; i++) snprintf(creds->password+i*2, 3, "%02x", random[16+i]);
    erase(random, sizeof(random)); return OB_API_OK;
}
int ob_api_tenant_register_credentials(ob_api_client *c,const char *name,const char *password,
                                       const char *email,char **out,ob_api_error *e) {
    if (!text_valid(name,128,0) || !text_valid(password,72,0) || strlen(password)<12 ||
        (email && !text_valid(email,254,0))) return bad_args(out,e);
    cJSON *j = one_string("name",name);
    if (j && (!cJSON_AddStringToObject(j,"password",password) ||
              (email && !cJSON_AddStringToObject(j,"email",email)))) { delete_json(j); j=NULL; }
    return send_object(c,"POST","/v1/tenants/register","",j,out,e);
}
int ob_api_tenant_register(ob_api_client *c,ob_api_credentials *creds,char **out,ob_api_error *e) {
    reset(e,out);
    if (!c || !creds || !out) return bad_args(out,e);
    int rc = ob_api_credentials_generate(creds,e);
    if (rc != OB_API_OK) return rc;
    /* Keep generated credentials on ALL outcomes: commit may precede lost reply. */
    return ob_api_tenant_register_credentials(c,creds->name,creds->password,NULL,out,e);
}
int ob_api_tenant_login(ob_api_client *c,const char *name,const char *password,char **out,ob_api_error *e) {
    if (!text_valid(name,128,0) || !text_valid(password,72,0)) return bad_args(out,e);
    cJSON *j = one_string("name",name);
    if (j && !cJSON_AddStringToObject(j,"password",password)) { delete_json(j); j=NULL; }
    return send_object(c,"POST","/v1/tenants/login","",j,out,e);
}
int ob_api_tenant_logout(ob_api_client *c,char **out,ob_api_error *e) {
    return ob_api_request(c,"POST","/v1/tenants/logout",NULL,"{}",out,e);
}
int ob_api_account_get(ob_api_client *c,char **out,ob_api_error *e) {
    return ob_api_request(c,"GET","/v1/me",NULL,NULL,out,e);
}
int ob_api_account_update(ob_api_client *c,const char *name,const char *email,char **out,ob_api_error *e) {
    if ((!name && !email) || (name && !text_valid(name,128,0)) || (email && !text_valid(email,254,1))) return bad_args(out,e);
    cJSON *j = cJSON_CreateObject();
    if (j && ((name && !cJSON_AddStringToObject(j,"name",name)) ||
              (email && !cJSON_AddStringToObject(j,"email",email)))) { delete_json(j); j=NULL; }
    return send_object(c,"PATCH","/v1/me",NULL,j,out,e);
}
int ob_api_account_password(ob_api_client *c,const char *password,char **out,ob_api_error *e) {
    if (!text_valid(password,72,0) || strlen(password)<12) return bad_args(out,e);
    return send_object(c,"POST","/v1/me/password",NULL,one_string("password",password),out,e);
}
int ob_api_capabilities(ob_api_client *c,char **out,ob_api_error *e) { return ob_api_request(c,"GET","/v1/capabilities",NULL,NULL,out,e); }
int ob_api_usage(ob_api_client *c,char **out,ob_api_error *e) { return ob_api_request(c,"GET","/v1/usage",NULL,NULL,out,e); }
int ob_api_broker_register(ob_api_client *c,const char *name,char **out,ob_api_error *e) {
    if (!text_valid(name,128,0)) return bad_args(out,e);
    return send_object(c,"POST","/v1/brokers",NULL,one_string("name",name),out,e);
}
int ob_api_broker_list(ob_api_client *c,char **out,ob_api_error *e) { return ob_api_request(c,"GET","/v1/brokers",NULL,NULL,out,e); }
int ob_api_broker_get(ob_api_client *c,const char *id,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"")) return bad_args(out,e);
    return ob_api_request(c,"GET",p,NULL,NULL,out,e);
}
int ob_api_broker_rename(ob_api_client *c,const char *id,const char *name,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"") || !text_valid(name,128,0)) return bad_args(out,e);
    return send_object(c,"PATCH",p,NULL,one_string("name",name),out,e);
}
int ob_api_broker_delete(ob_api_client *c,const char *id,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"")) return bad_args(out,e);
    return ob_api_request(c,"DELETE",p,NULL,NULL,out,e);
}
int ob_api_broker_token_rotate(ob_api_client *c,const char *id,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"/token")) return bad_args(out,e);
    return ob_api_request(c,"POST",p,NULL,"{}",out,e);
}
int ob_api_broker_usage(ob_api_client *c,const char *id,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"/usage")) return bad_args(out,e);
    return ob_api_request(c,"GET",p,NULL,NULL,out,e);
}
int ob_api_broker_offline(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"/offline") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"POST",p,token,"{}",out,e);
}
int ob_api_broker_heartbeat(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"/heartbeat") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"POST",p,token,"{}",out,e);
}
int ob_api_broker_sessions(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"brokers",id,"/sessions") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"GET",p,token,NULL,out,e);
}
int ob_api_session_create(ob_api_client *c,const char *id,const char *mode,char **out,ob_api_error *e) {
    if (!id_valid(id) || !mode || (strcmp(mode,"auto") && strcmp(mode,"never") && strcmp(mode,"force"))) return bad_args(out,e);
    cJSON *j = one_string("broker_id",id);
    if (j && !cJSON_AddStringToObject(j,"relay_mode",mode)) { delete_json(j); j=NULL; }
    return send_object(c,"POST","/v1/sessions",NULL,j,out,e);
}
int ob_api_session_get(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"sessions",id,"") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"GET",p,token,NULL,out,e);
}
int ob_api_session_capabilities(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"sessions",id,"/capabilities") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"GET",p,token,NULL,out,e);
}
int ob_api_session_delete(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"sessions",id,"") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"DELETE",p,token,NULL,out,e);
}
int ob_api_session_heartbeat(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"sessions",id,"/heartbeat") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"POST",p,token,"{}",out,e);
}
int ob_api_session_messages(ob_api_client *c,const char *id,const char *token,uint64_t after,char **out,ob_api_error *e) {
    char p[256],suffix[64]; snprintf(suffix,sizeof(suffix),"/messages?after=%" PRIu64,after);
    if (!route(p,sizeof(p),"sessions",id,suffix) || !token || !*token || after>9007199254740991ULL) return bad_args(out,e);
    return ob_api_request(c,"GET",p,token,NULL,out,e);
}
int ob_api_session_message_send(ob_api_client *c,const char *id,const char *token,uint64_t seq,const char *data,char **out,ob_api_error *e) {
    char p[256];
    if (!route(p,sizeof(p),"sessions",id,"/messages") || !token || !*token || !seq || seq>9007199254740991ULL ||
        !text_valid(data,32*1024,1)) return bad_args(out,e);
    cJSON *j = one_string("data",data);
    if (j && !cJSON_AddNumberToObject(j,"sequence",(double)seq)) { delete_json(j); j=NULL; }
    return send_object(c,"POST",p,token,j,out,e);
}
int ob_api_session_approve(ob_api_client *c,const char *id,const char *token,int relay,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"sessions",id,"/approve") || !token || !*token || (relay!=0 && relay!=1)) return bad_args(out,e);
    cJSON *j = cJSON_CreateObject();
    if (j && (!cJSON_AddBoolToObject(j,"peer_authenticated",1) || !cJSON_AddBoolToObject(j,"relay",relay))) { delete_json(j); j=NULL; }
    return send_object(c,"POST",p,token,j,out,e);
}
int ob_api_session_turn(ob_api_client *c,const char *id,const char *token,char **out,ob_api_error *e) {
    char p[256]; if (!route(p,sizeof(p),"sessions",id,"/turn") || !token || !*token) return bad_args(out,e);
    return ob_api_request(c,"POST",p,token,"{}",out,e);
}
