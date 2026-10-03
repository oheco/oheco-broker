#ifndef OB_API_H
#define OB_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Standalone management SDK. No Go runtime/callbacks or credential persistence.
 * Clients are immutable and support concurrent requests. The caller must wait
 * for all requests before destroying a client. Each request owns its curl handle.
 * libcurl initialization is process-once; the SDK never calls global cleanup.
 * Each SDK TLS context disables traffic-secret keylogging before its handshake.
 * Pristine curl may read SSLKEYLOGFILE and open/create an empty file at global
 * initialization; the SDK does not alter caller environment or unrelated TLS.
 */
typedef struct ob_api_client ob_api_client;

typedef struct {
    const char *base_url;     /* HTTPS origin; HTTP only literal loopback/localhost. */
    const char *tenant_token; /* Optional immutable fallback bearer, copied. */
    const char *ca_file;      /* Optional PEM trust bundle, copied; verification ALWAYS on. */
    long timeout_ms;          /* 0 = 15000; permitted 1..300000, includes entire response. */
} ob_api_options;

typedef enum {
    OB_API_OK = 0,
    OB_API_INVALID = -1,
    OB_API_NOMEM = -2,
    OB_API_TRANSPORT = -3,
    OB_API_HTTP = -4,
    OB_API_LIMIT = -5,
    OB_API_JSON = -6,
    OB_API_CRYPTO = -7
} ob_api_code;

typedef struct {
    int code;
    long http_status;    /* 0 until a response was received; preserved on HTTP errors. */
    int transport_code; /* CURLcode as integer; 0 when not applicable. */
    char message[128];   /* Redacted fixed diagnostic, never a URL/body/token/password. */
} ob_api_error;

#define OB_API_MAX_REQUEST_BYTES (256u * 1024u)
#define OB_API_MAX_RESPONSE_BYTES (1024u * 1024u)
#define OB_API_MAX_HEADER_BYTES (64u * 1024u)

ob_api_client *ob_api_client_create(const ob_api_options *options, ob_api_error *error);
void ob_api_client_destroy(ob_api_client *client);
void ob_api_response_free(char *json_response);

/* Only GET/POST/PATCH/DELETE; absolute API path starts /v1/, no percent encoding,
 * fragments, credentials, traversal or origin changes. NULL bearer uses the
 * client's tenant_token; "" explicitly disables authentication (register/login).
 * NULL body means no body. Response is bounded and validated JSON, or "" for
 * an empty successful response. On HTTP errors an optional validated JSON body
 * is returned as well; caller ALWAYS frees non-NULL output. Redirects/proxies
 * from the environment are disabled. Output is reset at entry: FREE any prior
 * response before reusing the same output variable.
 * Password-hash-bearing responses are rejected and are never returned.
 */
int ob_api_request(ob_api_client *client, const char *method, const char *path,
                   const char *bearer, const char *json_body,
                   char **json_response, ob_api_error *error);

/* Automatic credentials: tenant-UUIDv4 (43 chars), password 32 lowercase hex
 * chars (128 CSPRNG bits). Generated BEFORE the POST and retained even on HTTP/
 * transport failure: the server may have committed before its response was lost.
 * Caller owns these secrets and may recover with login. Never automatically retry
 * registration. No disk writes. For caller-managed pre-POST persistence, generate
 * first then call register_credentials. Registration/login JSON is {tenant,token}.
 * Login does not mutate the client; construct another client with the new token.
 */
typedef struct {
    char name[44];
    char password[33];
} ob_api_credentials;
void ob_api_credentials_clear(ob_api_credentials *credentials);
int ob_api_credentials_generate(ob_api_credentials *credentials, ob_api_error *error);
int ob_api_tenant_register_credentials(ob_api_client *client, const char *name,
                                       const char *password, const char *email,
                                       char **response, ob_api_error *error);
int ob_api_tenant_register(ob_api_client *client, ob_api_credentials *credentials,
                           char **response, ob_api_error *error);
int ob_api_tenant_login(ob_api_client *client, const char *name, const char *password,
                        char **response, ob_api_error *error);
int ob_api_tenant_logout(ob_api_client *client, char **response, ob_api_error *error);
int ob_api_account_get(ob_api_client *client, char **response, ob_api_error *error);
/* NULL fields in account update are omitted; at least one must be non-NULL. */
int ob_api_account_update(ob_api_client *client, const char *name, const char *email,
                          char **response, ob_api_error *error);
int ob_api_account_password(ob_api_client *client, const char *new_password,
                            char **response, ob_api_error *error);
int ob_api_capabilities(ob_api_client *client, char **response, ob_api_error *error);
int ob_api_usage(ob_api_client *client, char **response, ob_api_error *error);
int ob_api_broker_register(ob_api_client *client, const char *name,
                           char **response, ob_api_error *error);
int ob_api_broker_list(ob_api_client *client, char **response, ob_api_error *error);
int ob_api_broker_get(ob_api_client *client, const char *broker_id,
                      char **response, ob_api_error *error);
int ob_api_broker_rename(ob_api_client *client, const char *broker_id, const char *name,
                         char **response, ob_api_error *error);
int ob_api_broker_delete(ob_api_client *client, const char *broker_id,
                         char **response, ob_api_error *error);
/* Server permits rotation only when offline; online brokers return HTTP 409. */
int ob_api_broker_token_rotate(ob_api_client *client, const char *broker_id,
                               char **response, ob_api_error *error);
int ob_api_broker_usage(ob_api_client *client, const char *broker_id,
                        char **response, ob_api_error *error);
/* Device bearer is mandatory; never include the native peer password in a body. */
int ob_api_broker_offline(ob_api_client *client, const char *broker_id,
                          const char *device_token, char **response, ob_api_error *error);
int ob_api_broker_heartbeat(ob_api_client *client, const char *broker_id,
                            const char *device_token, char **response, ob_api_error *error);
int ob_api_broker_sessions(ob_api_client *client, const char *broker_id,
                           const char *device_token, char **response, ob_api_error *error);
int ob_api_session_create(ob_api_client *client, const char *broker_id,
                          const char *relay_mode, char **response, ob_api_error *error);
int ob_api_session_get(ob_api_client *client, const char *session_id,
                       const char *session_or_device_token, char **response, ob_api_error *error);
int ob_api_session_capabilities(ob_api_client *client, const char *session_id,
                                const char *session_or_device_token, char **response, ob_api_error *error);
int ob_api_session_delete(ob_api_client *client, const char *session_id,
                          const char *session_or_device_token, char **response, ob_api_error *error);
int ob_api_session_heartbeat(ob_api_client *client, const char *session_id,
                             const char *session_or_device_token, char **response, ob_api_error *error);
int ob_api_session_messages(ob_api_client *client, const char *session_id,
                            const char *session_or_device_token, uint64_t after,
                            char **response, ob_api_error *error);
int ob_api_session_message_send(ob_api_client *client, const char *session_id,
                                const char *session_or_device_token, uint64_t sequence,
                                const char *opaque_data, char **response, ob_api_error *error);
/* Call ONLY after successful native peer authentication. relay is 0 or 1. */
int ob_api_session_approve(ob_api_client *client, const char *session_id,
                           const char *device_token, int relay,
                           char **response, ob_api_error *error);
int ob_api_session_turn(ob_api_client *client, const char *session_id,
                        const char *session_or_device_token,
                        char **response, ob_api_error *error);

#ifdef __cplusplus
}
#endif
#endif
