#ifndef OB_WS_H
#define OB_WS_H
#include "ob_api.h"
#include <cjson/cJSON.h>
#include <stdint.h>
#define OB_WS_MAX_FRAME 262144u
#define OB_WS_MAX_QUEUE_BYTES (1024u * 1024u)
#define OB_WS_MAX_QUEUE_COUNT 64u
/* All calls, including destroy, belong to one control owner thread. The
 * cancellation callback may read atomics/lease state, but never calls curl. */
typedef struct ob_ws ob_ws;
typedef int (*ob_ws_cancel)(void *);
ob_ws *ob_ws_create(ob_api_client *api, int broker, const char *id,
                    const char *bearer, ob_ws_cancel cancel, void *arg);
void ob_ws_destroy(ob_ws *ws);
void ob_ws_disconnect(ob_ws *ws);
int ob_ws_connected(const ob_ws *ws);
int ob_ws_connect(ob_ws *ws, uint64_t consumed, long timeout_ms, ob_api_error *error);
/* Pump one bounded interval; queue validated push/result frames. */
int ob_ws_pump(ob_ws *ws, unsigned wait_ms, ob_api_error *error);
int ob_ws_begin(ob_ws *ws, const char *op, const cJSON *body,
                uint64_t *id, unsigned timeout_ms, ob_api_error *error);
/* 1=result available, 0=pending; body is caller-owned. */
int ob_ws_result(ob_ws *ws, uint64_t id, int *status, cJSON **body);
cJSON *ob_ws_pop(ob_ws *ws, const char *type);
int ob_ws_ack(ob_ws *ws, uint64_t consumed, ob_api_error *error);
#endif
