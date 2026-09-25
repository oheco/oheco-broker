/* Local detached API validation; no broker or third-party dependencies. */
#include "oheco_broker.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void expect(const oheco_broker_options *options, const char *out, const char *err,
                   oheco_broker_error expected) {
    uint32_t pid = 123;
    oheco_broker_diagnostic d;
    oheco_broker_error e = oheco_broker_spawn_detached("/nonexistent/ob-options-endpoint",
                                                    options, out, err, &pid, &d);
    assert(e == expected && d.code == expected && pid == 0);
}

int main(void) {
    oheco_broker_options o = {"/unused", NULL, NULL, 0, NULL, 0, 0};
    oheco_broker_diagnostic d;
    assert(oheco_broker_spawn_detached(NULL, &o, NULL, NULL, NULL, &d) == OB_INVALID_ARGUMENT);
    expect(NULL, NULL, NULL, OB_INVALID_ARGUMENT);
    expect(&o, NULL, NULL, OB_UNAVAILABLE);
    expect(&o, "", "", OB_UNAVAILABLE);
    expect(&o, "relative/日志", "/absolute/错误", OB_UNAVAILABLE);
    o.stdin_enabled = 1; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.stdin_enabled = -1; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.stdin_enabled = 2; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.stdin_enabled = 0;
    const char bad[] = {(char)0xed, (char)0xa0, (char)0x80, 0};
    expect(&o, bad, NULL, OB_INVALID_ARGUMENT);
    expect(&o, NULL, bad, OB_INVALID_ARGUMENT);
    o.executable = ""; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.executable = bad; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.executable = "/unused";
    o.cwd = bad; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT); o.cwd = NULL;
    o.argc = 1; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    const char *args[] = {NULL}; o.args = args;
    expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    args[0] = bad; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.argc = 4097; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.argc = 0; o.args = NULL;
    o.envc = 1; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    oheco_broker_env env[] = {{"X", "1"}, {"X", "2"}};
    o.env = env; o.envc = 2; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.envc = 1; env[0].key = "X=Y"; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    env[0].key = ""; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    env[0].key = "X"; env[0].value = NULL; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.envc = 4097; expect(&o, NULL, NULL, OB_INVALID_ARGUMENT);
    o.envc = 0; o.env = NULL;
    /* Neither log alone exceeds the limit, but their combined START does. */
    size_t n = 524288;
    char *large = malloc(n + 1); assert(large);
    memset(large, 'x', n); large[n] = 0;
    expect(&o, large, NULL, OB_UNAVAILABLE);
    expect(&o, large, large, OB_LIMIT);
    free(large);
    puts("PASS detached options, null sinks, UTF-8, counts, combined payload limit");
    return 0;
}
