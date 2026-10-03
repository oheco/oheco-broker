#ifndef OB_JSON_H
#define OB_JSON_H
#include <stddef.h>
#include <stdint.h>
#include <cjson/cJSON.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Internal SDK adapter, not a public management API. All SDK cJSON parsing
 * shares this lock: pristine upstream has process-global error bookkeeping.
 * length excludes the final NUL; input must provide length+1 accessible bytes.
 * No custom cJSON allocator hooks or locale changes after threads start.
 * The returned tree is caller-owned and does not retain the parser lock. */
cJSON *ob_json_parse_complete(const char *text, size_t length);
/* A parsed, duplicate-free object is required. Check the original top-level
 * field's unsigned decimal spelling, not rounded cJSON doubles: no sign,
 * decimal point or exponent. Body numbers/opaque strings are not restricted.
 * Escaped ASCII field names remain equivalent JSON keys. No cJSON global state
 * is touched; bounded scans require no allocator or additional parser lock. */
int ob_json_uint_field(const char *text, size_t length, const char *field,
                       uint64_t min, uint64_t max, uint64_t *value);
#ifdef __cplusplus
}
#endif
#endif
