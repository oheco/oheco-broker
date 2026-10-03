/* Native signed runtime checks consumed by scripts/build-curl-deps.sh.
 * Copyright 2026 oheco contributors. SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <time.h>
int main(int argc, char **argv) {
    (void)argc;
    char original = argv[0][0];
    argv[0][0] = ' ';
    int writable = argv[0][0] == ' ';
    argv[0][0] = original;
    time_t t = (time_t)-1;
    printf("%d %d\n", writable, !(t < (time_t)0));
    return 0;
}
