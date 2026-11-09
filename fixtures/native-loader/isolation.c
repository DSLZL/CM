#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(test) do { if (!(test)) { fprintf(stderr, "isolation.c:%d: %s (errno=%d)\n", __LINE__, #test, errno); exit(1); } } while (0)

static void absent(const char *path) {
    CHECK(access(path, F_OK) == -1 && errno == ENOENT);
}

static void boundary(int argc, char **argv) {
    const char *names[] = {"user", "mnt", "pid", "ipc", "uts", "net"};
    CHECK(getuid() == 1000 && getgid() == 1000);
    for (int i = 0; i < 6; i++) {
        char path[64], actual[128];
        CHECK(snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]) > 0);
        ssize_t size = readlink(path, actual, sizeof(actual) - 1);
        CHECK(size > 0);
        actual[size] = 0;
        CHECK(strcmp(actual, argv[i + 2]) != 0);
    }
    FILE *status = fopen("/proc/self/status", "r");
    CHECK(status != NULL);
    char line[512], name[32];
    unsigned long long value;
    int capabilities = 0;
    while (fgets(line, sizeof(line), status)) {
        if (sscanf(line, "Cap%31[^:]: %llx", name, &value) == 2) {
            CHECK(value == 0);
            capabilities++;
        }
    }
    CHECK(fclose(status) == 0 && capabilities == 5);
    int input = open("/input/marker", O_RDONLY);
    char marker[16] = {0};
    CHECK(input >= 0 && read(input, marker, sizeof(marker)) == 9);
    CHECK(strcmp(marker, "immutable") == 0 && close(input) == 0);
    CHECK(open("/input/marker", O_WRONLY) == -1 && errno == EROFS);
    const char *tools[] = {"/usr/bin/cc", "/usr/bin/gcc", "/usr/bin/cargo", "/usr/bin/rustc",
        "/usr/bin/python3", "/usr/bin/ld", "/usr/bin/sccache", "/run/host", "/sys", "/etc/resolv.conf"};
    for (size_t i = 0; i < sizeof(tools) / sizeof(tools[0]); i++) absent(tools[i]);
    for (int i = 8; i < argc; i++) {
        absent(argv[i]);
        char path[4096];
        CHECK(snprintf(path, sizeof(path), "/proc/1/root%s", argv[i]) < (int)sizeof(path));
        absent(path);
        CHECK(snprintf(path, sizeof(path), "/proc/self/root%s", argv[i]) < (int)sizeof(path));
        absent(path);
    }
}

int main(int argc, char **argv) {
    CHECK(argc == 11);
    alarm(20);
    boundary(argc, argv);
    const char *tools[] = {"/usr/bin/cc", "/usr/bin/cargo"};
    for (int i = 0; i < 2; i++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            boundary(argc, argv);
            execl(tools[i], tools[i], "--version", (char *)NULL);
            _exit(errno == ENOENT ? 0 : 1);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    address.sin_port = htons((unsigned short)strtoul(argv[1], NULL, 10));
    int external = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(external >= 0 && connect(external, (void *)&address, sizeof(address)) == -1);
    int denied_errno = errno;
    CHECK(denied_errno == ECONNREFUSED || denied_errno == ENETUNREACH);
    CHECK(close(external) == 0);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    address.sin_port = 0;
    CHECK(bind(listener, (void *)&address, sizeof(address)) == 0 && listen(listener, 1) == 0);
    socklen_t length = sizeof(address);
    CHECK(getsockname(listener, (void *)&address, &length) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        boundary(argc, argv);
        int client = socket(AF_INET, SOCK_STREAM, 0);
        char response[4];
        CHECK(client >= 0 && connect(client, (void *)&address, sizeof(address)) == 0);
        CHECK(send(client, "ping", 4, MSG_NOSIGNAL) == 4 && recv(client, response, 4, MSG_WAITALL) == 4);
        CHECK(memcmp(response, "pong", 4) == 0 && close(client) == 0);
        _exit(0);
    }
    struct sockaddr_in peer;
    length = sizeof(peer);
    int client = accept(listener, (void *)&peer, &length), status;
    char request[4];
    CHECK(client >= 0 && recv(client, request, 4, MSG_WAITALL) == 4 && memcmp(request, "ping", 4) == 0);
    CHECK(send(client, "pong", 4, MSG_NOSIGNAL) == 4 && close(client) == 0 && close(listener) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("{\"status\":\"pass\",\"internal_port\":%u,\"canary_errno\":%d,\"denied_compiler_execs\":2,\"namespace_checks\":24}\n",
        ntohs(address.sin_port), denied_errno);
    return 0;
}
