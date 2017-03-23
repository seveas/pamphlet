#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *real_filename(const char *filename) {
    static char *test_etc = NULL;
    static char buffer[PATH_MAX];

    if(!test_etc) {
        test_etc = getenv("TEST_ETC");
        if(!test_etc) {
            fprintf(stderr, "TEST_ETC not set\n");
            exit(1);
        }
    }

    if(strncmp(filename, "/etc/pam.d/", 11) != 0 &&
       strcmp(filename, "/etc/passwd") != 0 &&
       strcmp(filename, "/etc/shadow") != 0 &&
       strcmp(filename, "/etc/group") != 0 &&
       strcmp(filename, "/etc/gshadow") != 0)
        
        return (char*)filename;

    snprintf(buffer, PATH_MAX, "%s/%s", test_etc, filename+5);
    return buffer;
}

int open(const char *filename, int flags) {
    static int (*real_open)(const char *filename, int flags);
    if(!real_open)
        real_open = dlsym(RTLD_NEXT, "open");

    return real_open(real_filename(filename), flags);
}

FILE *fopen(const char *filename, const char *mode) {
    static FILE* (*real_fopen)(const char *path, const char *mode);
    if(!real_fopen)
        real_fopen = dlsym(RTLD_NEXT, "fopen");
    return real_fopen(real_filename(filename), mode);
}
