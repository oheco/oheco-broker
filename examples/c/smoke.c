#define _POSIX_C_SOURCE 200809L
#include "oheco_broker.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int report(const char *what, oheco_broker_error e, const oheco_broker_diagnostic *d) {
    fprintf(stderr, "%s: %s stage=%s native=%d %s\n", what, oheco_broker_error_name(e),
            d->stage, d->native_error, d->message);
    return 1;
}
static oheco_broker_error launch(const char *endpoint, const char *shell, const char *script,
                       int input, oheco_broker_process **p, oheco_broker_diagnostic *d) {
    const char *args[] = {"-c", script};
    oheco_broker_options o = {shell, NULL, args, 2, NULL, 0, input};
    return oheco_broker_start(endpoint, &o, p, d);
}
static int collect(oheco_broker_process *p, const char *out, const char *err, int code) {
    size_t sizes[2] = {0, 0};
    const char *expected[2] = {out, err};
    oheco_broker_diagnostic d;
    for (;;) {
        oheco_broker_event event; oheco_broker_error e = oheco_broker_read_event(p, 10000, &event, &d);
        if (e) return report("read", e, &d);
        if (event.type == OHECO_BROKER_EVENT_EXIT) {
            if (event.result.reason != 0 || event.result.exit_code != code ||
                sizes[0] != strlen(out) || sizes[1] != strlen(err)) {
                fprintf(stderr, "Unexpected exit or output lengths\n"); return 1;
            }
            return 0;
        }
        unsigned stream = event.type == OHECO_BROKER_EVENT_STDOUT ? 0 : 1;
        size_t wanted = strlen(expected[stream]);
        if (event.size > wanted - sizes[stream] || memcmp(event.data, expected[stream] + sizes[stream], event.size)) {
            fprintf(stderr, "Unexpected output bytes\n"); return 1;
        }
        sizes[stream] += event.size;
    }
}
static void pause_ms(long ms) {
    struct timespec t = {ms / 1000, (ms % 1000) * 1000000};
    while (nanosleep(&t, &t) < 0 && errno == EINTR) {}
}
struct cancel_args { oheco_broker_process *p; oheco_broker_error result; oheco_broker_diagnostic diagnostic; };
static void *cancel_later(void *value) {
    struct cancel_args *a = value; pause_ms(100);
    a->result = oheco_broker_cancel(a->p, &a->diagnostic); return NULL;
}
struct writer_args { oheco_broker_process *p; oheco_broker_error result; };
static void *write_lots(void *value) {
    struct writer_args *a = value;
    size_t n = 16 * 1024 * 1024;
    unsigned char *b = malloc(n);
    if (!b) { a->result = OHECO_BROKER_ERR_IO; return NULL; }
    memset(b, 'x', n); a->result = oheco_broker_write_stdin(a->p, b, n, NULL); free(b); return NULL;
}
static int suite(const char *endpoint, const char *shell) {
    oheco_broker_process *p = NULL; oheco_broker_diagnostic d; oheco_broker_error e; oheco_broker_exit result;
    e = launch("/nonexistent/oheco-broker-smoke-endpoint", shell, "exit 0", 0, &p, &d);
    if (e != OHECO_BROKER_ERR_UNAVAILABLE || p) return report("missing discovery must be UNAVAILABLE", e, &d);
    const char invalid[] = {(char)0xed, (char)0xa0, (char)0x80, 0};
    oheco_broker_options invalid_options = {invalid, NULL, NULL, 0, NULL, 0, 0};
    e = oheco_broker_start(endpoint, &invalid_options, &p, &d);
    if (e != OHECO_BROKER_ERR_INVALID_ARGUMENT || p) return report("invalid UTF-8", e, &d);
    puts("PASS invalid discovery and UTF-8");

    e = launch(endpoint, shell, "printf 'hello'; printf 'error' >&2; exit 7", 0, &p, &d);
    if (e) return report("stdout/stderr start", e, &d);
    int failed = collect(p, "hello", "error", 7); oheco_broker_release(p); if (failed) return 1;
    puts("PASS stdout/stderr and nonzero exit");

    e = launch(endpoint, shell, "IFS= read -r line; printf '%s' \"$line\"", 1, &p, &d);
    if (e) return report("stdin start", e, &d);
    const char input[] = "stdin-中文-🚀\n";
    e = oheco_broker_write_stdin(p, input, sizeof(input) - 1, &d);
    if (!e) e = oheco_broker_close_stdin(p, &d);
    if (e) { oheco_broker_release(p); return report("stdin", e, &d); }
    failed = collect(p, "stdin-中文-🚀", "", 0); oheco_broker_release(p); if (failed) return 1;
    puts("PASS stdin and EOF");

    const char *temp = getenv("TMPDIR");
    if (!temp || !*temp) { fprintf(stderr, "Set TMPDIR for isolated Unicode cwd test\n"); return 1; }
    size_t path_size = strlen(temp) + 80;
    char *root = malloc(path_size), *cwd = malloc(path_size);
    if (!root || !cwd) { free(root); free(cwd); return 1; }
    snprintf(root, path_size, "%s/ob-c-smoke.XXXXXX", temp);
    if (!mkdtemp(root)) { perror("mkdtemp"); free(root); free(cwd); return 1; }
    snprintf(cwd, path_size, "%s/目录-🚀", root);
    if (mkdir(cwd, 0700) != 0) { perror("mkdir"); rmdir(root); free(root); free(cwd); return 1; }
    const char *args[] = {"-c", "[ \"$PWD\" = \"$EXPECTED_CWD\" ] || exit 91; printf '%s|%s' \"$1\" \"$OHECO_TEST\"", "smoke", "参数-🚀"};
    oheco_broker_env env[] = {{"OHECO_TEST", "环境-中文"}, {"EXPECTED_CWD", cwd}};
    oheco_broker_options options = {shell, cwd, args, 4, env, 2, 0};
    e = oheco_broker_start(endpoint, &options, &p, &d);
    failed = e ? report("Unicode start", e, &d) : collect(p, "参数-🚀|环境-中文", "", 0);
    if (!e) oheco_broker_release(p);
    rmdir(cwd); rmdir(root); free(cwd); free(root); if (failed) return 1;
    puts("PASS args/env/cwd Unicode");

    e = launch(endpoint, shell, "i=0; while [ \"$i\" -lt 8192 ]; do printf '0123456789abcdef0123456789abcdef'; i=$((i+1)); done", 0, &p, &d);
    if (e) return report("large output start", e, &d);
    size_t total = 0;
    for (;;) {
        oheco_broker_event event; e = oheco_broker_read_event(p, 10000, &event, &d);
        if (e) { oheco_broker_release(p); return report("large output read", e, &d); }
        if (event.type == OHECO_BROKER_EVENT_EXIT) {
            failed = event.result.reason != 0 || event.result.exit_code != 0 || total != 262144; break;
        }
        if (event.type != OHECO_BROKER_EVENT_STDOUT) { failed = 1; break; }
        const char digits[] = "0123456789abcdef";
        for (size_t i = 0; i < event.size; i++) if (event.data[i] != (unsigned char)digits[(total + i) % 16]) failed = 1;
        total += event.size;
    }
    oheco_broker_release(p); if (failed) { fprintf(stderr, "Large output mismatch (%zu bytes)\n", total); return 1; }
    puts("PASS >pipe output byte-for-byte");

    e = launch(endpoint, shell, "i=0; while [ \"$i\" -lt 8192 ]; do printf '0123456789abcdef0123456789abcdef' >&2; i=$((i+1)); done", 0, &p, &d);
    if (e) return report("wait drain start", e, &d);
    e = oheco_broker_wait(p, 20000, &result, &d); oheco_broker_release(p);
    if (e) return report("wait drain", e, &d);
    if (result.reason || result.exit_code) return 1;
    puts("PASS wait drains unconsumed >pipe stderr");

    e = launch(endpoint, shell, "while :; do :; done", 0, &p, &d);
    if (e) return report("cancel start", e, &d);
    e = oheco_broker_wait(p, 20, &result, &d);
    if (e != OHECO_BROKER_ERR_TIMEOUT) { oheco_broker_release(p); return report("wait timeout", e, &d); }
    struct cancel_args a = {p, OHECO_BROKER_OK, {0}}; pthread_t thread;
    int rc = pthread_create(&thread, NULL, cancel_later, &a);
    if (rc) { oheco_broker_release(p); fprintf(stderr, "pthread_create: %d\n", rc); return 1; }
    e = oheco_broker_wait(p, 10000, &result, &d);
    pthread_join(thread, NULL); oheco_broker_release(p);
    if (a.result) return report("concurrent cancel", a.result, &a.diagnostic);
    if (e) return report("cancel wait", e, &d);
    if (result.reason != 2) { fprintf(stderr, "Expected cancelled EXIT\n"); return 1; }
    puts("PASS timeout does not cancel; concurrent cancel/read");

    e = launch(endpoint, shell, "while :; do :; done", 1, &p, &d);
    if (e) return report("blocked stdin start", e, &d);
    struct writer_args writer = {p, OHECO_BROKER_OK}; pthread_t producer;
    rc = pthread_create(&producer, NULL, write_lots, &writer);
    if (rc) { oheco_broker_release(p); return 1; }
    pause_ms(100);
    e = oheco_broker_cancel(p, &d); pthread_join(producer, NULL);
    /* If a frame cannot finish within its deadline, disconnect is deliberately
     * used to cancel; neither thread may hang indefinitely or corrupt framing. */
    if (e == OHECO_BROKER_OK) {
        e = oheco_broker_wait(p, 10000, &result, &d);
        failed = e == OHECO_BROKER_OK ? result.reason != 2 :
                 e != OHECO_BROKER_ERR_LIMIT && e != OHECO_BROKER_ERR_CONNECTION_LOST;
    } else failed = e != OHECO_BROKER_ERR_TIMEOUT && e != OHECO_BROKER_ERR_CONNECTION_LOST;
    oheco_broker_release(p);
    if (failed) return report("cancel during blocked input", e, &d);
    puts("PASS bounded cancel during blocked stdin");
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "discovery")) {
        oheco_broker_process *p; oheco_broker_diagnostic d;
        oheco_broker_error e = launch(argv[2], "/unused", "exit 0", 0, &p, &d);
        if (!e) oheco_broker_release(p);
        printf("%s stage=%s native=%d\n", oheco_broker_error_name(e), d.stage, d.native_error);
        return e == OHECO_BROKER_ERR_UNAVAILABLE ? 0 : 1;
    }
    if (argc == 3 && !strcmp(argv[1], "resume")) {
        oheco_broker_process *p; oheco_broker_diagnostic d;
        oheco_broker_error e = launch(argv[2], "/unused", "", 0, &p, &d);
        if (e) return report("resume start", e, &d);
        oheco_broker_event event;
        e = oheco_broker_read_event(p, 20, &event, &d);
        if (e != OHECO_BROKER_ERR_TIMEOUT) { oheco_broker_release(p); return report("expected partial-frame timeout", e, &d); }
        int failed = collect(p, "resume", "", 0);
        oheco_broker_release(p); return failed;
    }
    if (argc == 4 && !strcmp(argv[1], "suite")) return suite(argv[2], argv[3]);
    if (argc >= 4 && !strcmp(argv[1], "run")) {
        oheco_broker_options options = {argv[3], NULL, (const char *const *)(argv + 4), (size_t)argc - 4, NULL, 0, 0};
        oheco_broker_process *p; oheco_broker_diagnostic d; oheco_broker_error e = oheco_broker_start(strcmp(argv[2], "-") ? argv[2] : NULL, &options, &p, &d);
        if (e) return report("start", e, &d);
        for (;;) {
            oheco_broker_event event; e = oheco_broker_read_event(p, -1, &event, &d);
            if (e) { oheco_broker_release(p); return report("read", e, &d); }
            if (event.type == OHECO_BROKER_EVENT_EXIT) {
                oheco_broker_release(p);
                return event.result.reason == 0 ? event.result.exit_code : 128;
            }
            FILE *stream = event.type == OHECO_BROKER_EVENT_STDOUT ? stdout : stderr;
            if (fwrite(event.data, 1, event.size, stream) != event.size) { oheco_broker_release(p); return 1; }
        }
    }
    fprintf(stderr, "Usage:\n  %s suite ENDPOINT SHELL\n  %s discovery BAD_ENDPOINT\n  %s run ENDPOINT_OR_DASH EXECUTABLE [ARG...]\n", argv[0], argv[0], argv[0]);
    return 2;
}
