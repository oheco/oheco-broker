#include "ob_json.h"
#include <pthread.h>
#include <stdint.h>

static pthread_mutex_t ob_json_parse_lock = PTHREAD_MUTEX_INITIALIZER;

cJSON *ob_json_parse_complete(const char *text, size_t length)
{
    if (!text || length == SIZE_MAX || text[length] != '\0') return NULL;
    const char *end = NULL;
    pthread_mutex_lock(&ob_json_parse_lock);
    cJSON *result = cJSON_ParseWithLengthOpts(text, length + 1, &end, 1);
    pthread_mutex_unlock(&ob_json_parse_lock);
    return result;
}

static int json_space(unsigned char c)
{ return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static size_t string_end(const char *text, size_t length, size_t at)
{
    if (at >= length || text[at] != '"') return length;
    for (++at; at < length; ++at) {
        if (text[at] == '"') return at + 1;
        if (text[at] == '\\') { if (++at >= length) break; }
    }
    return length;
}
static int hex_digit(unsigned char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int ascii_key_equal(const char *text, size_t begin, size_t end, const char *field)
{
    /* end is one past the closing quote. Validated non-ASCII keys cannot
     * match these internal ASCII schema names, including surrogate pairs. */
    if (end <= begin + 1) return 0;
    size_t at = begin + 1, finish = end - 1, key = 0;
    while (at < finish) {
        unsigned char c = (unsigned char)text[at++];
        if (c == '\\') {
            if (at >= finish) return 0;
            c = (unsigned char)text[at++];
            if (c == 'u') {
                if (finish - at < 4) return 0;
                unsigned code = 0;
                for (unsigned i = 0; i < 4; ++i) {
                    int digit = hex_digit((unsigned char)text[at++]); if (digit < 0) return 0;
                    code = code * 16 + (unsigned)digit;
                }
                if (!code || code > 127) return 0;
                c = (unsigned char)code;
            } else if (c == 'b') c = '\b';
            else if (c == 'f') c = '\f';
            else if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
            else if (c != '"' && c != '\\' && c != '/') return 0;
        }
        if (!field[key] || c != (unsigned char)field[key++]) return 0;
    }
    return field[key] == '\0';
}
static size_t value_end(const char *text, size_t length, size_t at)
{
    size_t depth = 0;
    for (; at < length; ++at) {
        unsigned char c = (unsigned char)text[at];
        if (c == '"') {
            size_t end = string_end(text, length, at);
            if (end == length) return length;
            at = end - 1;
        } else if (c == '{' || c == '[') {
            if (depth == SIZE_MAX) return length;
            ++depth;
        } else if (c == '}' || c == ']') {
            if (!depth) return at;
            --depth;
        } else if (c == ',' && !depth) return at;
    }
    return length;
}
int ob_json_uint_field(const char *text, size_t length, const char *field,
                       uint64_t min, uint64_t max, uint64_t *value)
{
    if (value) *value = 0;
    if (!text || !field || !*field || min > max) return 0;
    size_t at = 0;
    while (at < length && json_space((unsigned char)text[at])) ++at;
    if (at >= length || text[at++] != '{') return 0;
    while (at < length) {
        while (at < length && json_space((unsigned char)text[at])) ++at;
        if (at >= length || text[at] != '"') return 0;
        size_t begin = at, end = string_end(text, length, at);
        if (end >= length) return 0;
        int match = ascii_key_equal(text, begin, end, field); at = end;
        while (at < length && json_space((unsigned char)text[at])) ++at;
        if (at >= length || text[at++] != ':') return 0;
        while (at < length && json_space((unsigned char)text[at])) ++at;
        begin = at; end = value_end(text, length, at);
        if (end >= length) return 0;
        if (match) {
            while (end > begin && json_space((unsigned char)text[end-1])) --end;
            if (begin == end || (end-begin > 1 && text[begin] == '0')) return 0;
            uint64_t result = 0;
            for (size_t i = begin; i < end; ++i) {
                unsigned char c = (unsigned char)text[i]; if (c < '0' || c > '9') return 0;
                unsigned digit = c - '0';
                if (result > (UINT64_MAX-digit)/10) return 0;
                result = result*10 + digit;
            }
            if (result < min || result > max) return 0;
            if (value) *value = result;
            return 1;
        }
        at = end;
        if (text[at] != ',') return 0;
        ++at;
    }
    return 0;
}
