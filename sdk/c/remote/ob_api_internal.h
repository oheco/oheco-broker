#ifndef OB_API_INTERNAL_H
#define OB_API_INTERNAL_H
#include "ob_api.h"
#include <curl/curl.h>
/* Immutable after creation. Private transports borrow this configuration;
 * no public layout or ownership contract is exposed. */
struct ob_api_client {
    char *base_url, *tenant_token, *ca_file;
    char *localhost_resolve;
    long timeout_ms;
};
CURLcode ob_api_secure_ssl_context(CURL *easy, void *context, void *user);
typedef int (*ob_api_cancel_callback)(void *user);
int ob_api_request_cancelled(ob_api_client *client, const char *method,
                             const char *path, const char *bearer,
                             const char *body, char **out, ob_api_error *error,
                             ob_api_cancel_callback cancel, void *user);
#endif
