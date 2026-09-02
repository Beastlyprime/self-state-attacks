// Minimal Landlock write allow-list launcher for the prevention baseline.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

static int ll_create(const struct landlock_ruleset_attr *attr, size_t size,
                     unsigned int flags) {
    return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static int ll_add(int fd, enum landlock_rule_type type, const void *attr,
                  unsigned int flags) {
    return syscall(__NR_landlock_add_rule, fd, type, attr, flags);
}

static int ll_restrict(int fd, unsigned int flags) {
    return syscall(__NR_landlock_restrict_self, fd, flags);
}

static __u64 handled_for_abi(int abi) {
    __u64 rights = LANDLOCK_ACCESS_FS_WRITE_FILE |
                   LANDLOCK_ACCESS_FS_REMOVE_DIR |
                   LANDLOCK_ACCESS_FS_REMOVE_FILE |
                   LANDLOCK_ACCESS_FS_MAKE_CHAR |
                   LANDLOCK_ACCESS_FS_MAKE_DIR |
                   LANDLOCK_ACCESS_FS_MAKE_REG |
                   LANDLOCK_ACCESS_FS_MAKE_SOCK |
                   LANDLOCK_ACCESS_FS_MAKE_FIFO |
                   LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                   LANDLOCK_ACCESS_FS_MAKE_SYM;
    if (abi >= 2)
        rights |= LANDLOCK_ACCESS_FS_REFER;
    if (abi >= 3)
        rights |= LANDLOCK_ACCESS_FS_TRUNCATE;
    return rights;
}

static int add_path_rule(int ruleset_fd, const char *path, __u64 handled) {
    struct stat st;
    int path_fd = open(path, O_PATH | O_CLOEXEC);
    if (path_fd < 0) {
        fprintf(stderr, "open allow-write path %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (fstat(path_fd, &st) != 0) {
        fprintf(stderr, "stat allow-write path %s: %s\n", path, strerror(errno));
        close(path_fd);
        return -1;
    }
    __u64 allowed = handled;
    if (!S_ISDIR(st.st_mode)) {
        allowed &= LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    struct landlock_path_beneath_attr rule = {
        .allowed_access = allowed,
        .parent_fd = path_fd,
    };
    int rc = ll_add(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    if (rc != 0)
        fprintf(stderr, "add Landlock rule %s: %s\n", path, strerror(errno));
    close(path_fd);
    return rc;
}

static void usage(const char *program) {
    fprintf(stderr,
            "usage: %s --probe | [--allow-write PATH ...] -- COMMAND [ARG ...]\n",
            program);
}

int main(int argc, char **argv) {
    int abi = ll_create(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (argc == 2 && strcmp(argv[1], "--probe") == 0) {
        if (abi < 0) {
            printf("{\"abi\":0,\"errno\":%d}\n", errno);
            return 1;
        }
        printf("{\"abi\":%d}\n", abi);
        return 0;
    }
    if (abi < 1) {
        fprintf(stderr, "Landlock unavailable: %s\n", strerror(errno));
        return 125;
    }

    const char **paths = calloc((size_t)argc, sizeof(*paths));
    if (!paths)
        return 125;
    int npaths = 0;
    int command_index = -1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--allow-write") == 0 && i + 1 < argc) {
            paths[npaths++] = argv[++i];
        } else if (strcmp(argv[i], "--") == 0) {
            command_index = i + 1;
            break;
        } else {
            usage(argv[0]);
            free(paths);
            return 125;
        }
    }
    if (command_index < 0 || command_index >= argc) {
        usage(argv[0]);
        free(paths);
        return 125;
    }

    __u64 handled = handled_for_abi(abi);
    struct landlock_ruleset_attr ruleset = {.handled_access_fs = handled};
    int ruleset_fd = ll_create(&ruleset, sizeof(ruleset), 0);
    if (ruleset_fd < 0) {
        fprintf(stderr, "create Landlock ruleset: %s\n", strerror(errno));
        free(paths);
        return 125;
    }
    for (int i = 0; i < npaths; i++) {
        if (add_path_rule(ruleset_fd, paths[i], handled) != 0) {
            close(ruleset_fd);
            free(paths);
            return 125;
        }
    }
    free(paths);
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        fprintf(stderr, "PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
        close(ruleset_fd);
        return 125;
    }
    if (ll_restrict(ruleset_fd, 0) != 0) {
        fprintf(stderr, "restrict self with Landlock: %s\n", strerror(errno));
        close(ruleset_fd);
        return 125;
    }
    close(ruleset_fd);
    execvp(argv[command_index], &argv[command_index]);
    fprintf(stderr, "exec %s: %s\n", argv[command_index], strerror(errno));
    return 126;
}
