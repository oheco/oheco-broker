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
#endif
