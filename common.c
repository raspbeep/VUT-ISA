/**
 *
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file common.c
 *
 * @brief
 */
#include <sys/socket.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "errors.h"
#include "common.h"

void construct_dns_question(unsigned char *buffer) {
    struct Question *q_info = (struct Question *)buffer;
    q_info->q_type = htons(1);  // a record
    q_info->q_class = htons(1); // internet
}

void construct_dns_header(unsigned char *buffer, unsigned int id, uint16_t n_questions) {
    // set pointer of dns header to the beginning of buffer
    struct DNSHeader *header = (struct DNSHeader *)buffer;
    // 16b aligned fields
    header->id = (unsigned short) htons(id);

    header->qr = 0;                             // query
    header->opcode = 0;                         // standard query
    header->aa = 0;                             // not authoritative
    header->tc = 0;                             // not truncated
    header->rd = 0;                             // no recursion
    header->ra = 0;                             // no recursion
    header->z = 0;                              // no special use
    header->ad = 0;                             // no authenticated data
    header->cd = 0;                             // checking disabled
    header->r_code = 0;                         // no error

    header->q_count = htons(n_questions);       // 1 question
    header->ans_count = 0;                      // 0 answers
    header->ns_count = 0;                       // 0 nameserver RRs
    header->ar_count = 0;                       // 0 additional RRs
}

int open_file(const char *path, const char *read_mode, FILE **fptr) {
    if(!strcmp(read_mode, "rb")) {
        // check reading permission
        if (access(path, R_OK)) {
            return E_RD_PERM;
        }
    }
    *fptr = fopen(path, read_mode);
    if (*fptr == NULL) return E_OPEN_FILE;
    return EXIT_OK;
}

int send_packet(int sock, struct sockaddr_in *addr, unsigned char *buffer, int pos) {
    if (sendto(sock, buffer, pos, 0, (const struct sockaddr *)addr, sizeof(*addr)) != pos) {
        return E_PKT_SEND;
    }
    return EXIT_OK;
}

int get_packet(int sock, struct sockaddr_in *addr, unsigned char *buffer, ssize_t *rec_len, socklen_t *addr_len) {
    if ((*rec_len = recvfrom(sock, buffer, DNS_SIZE, 0, (struct sockaddr *)addr, addr_len)) <= 0) {
        if (errno == EAGAIN) {
            return E_TIMEOUT;
        } else {
            return E_PKT_REC;
        }
    }
    return EXIT_OK;
}

int set_timeout(int sock_fd) {
    struct timeval timeout = {TIMEOUT_S,0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return E_TIMEOUT;
    }
    return EXIT_OK;
}

int unset_timeout(int sock_fd) {
    struct timeval timeout = {0,0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return E_TIMEOUT;
    }
    return EXIT_OK;
}

int handle_error(const int err_n) {
    switch (err_n) {
        case E_INT:
            fprintf(stderr, "Err: Internal error\n");
            return E_INT;
        case EXIT_HELP:
            return EXIT_OK;
        case E_NUM_ARGS:
            fprintf(stderr, "Err: Invalid number of arguments\n");
            return E_NUM_ARGS;
        case E_INV_ARGS:
            fprintf(stderr, "Err: Invalid arguments\n");
            return E_INV_ARGS;
        case E_RE_U_ARGS:
            fprintf(stderr, "Err: Redefinition of -u flag\n");
            return E_RE_U_ARGS;
        case E_POS_ARG:
            fprintf(stderr, "Err: Invalid number of positional arguments\n");
            return E_POS_ARG;
//        case E_WR_PERM:
//            fprintf(stderr, "Err: \n");
//            return E_WR_PERM;
        case E_OPEN_FILE:
            fprintf(stderr, "Err: Unable to open file\n");
            return E_OPEN_FILE;
        case E_RD_FILE:
            fprintf(stderr, "Err: Unable to read file\n");
            return E_RD_FILE;
        case E_HOST_LEN:
            fprintf(stderr, "Err: Invalid base host length(must bet <=63)\n");
            return E_HOST_LEN;
        case E_PKT_SEND:
            fprintf(stderr, "Err: \n");
            return E_PKT_SEND;
        case E_PKT_REC:
            fprintf(stderr, "Err: \n");
            return E_PKT_REC;
        case E_INIT_CONN:
            fprintf(stderr, "Err: \n");
            return E_INIT_CONN;
        case E_SOCK_CRT:
            fprintf(stderr, "Err: \n");
            return E_SOCK_CRT;
        case E_BIND:
            fprintf(stderr, "Err: \n");
            return E_BIND;
        case E_TIMEOUT:
            fprintf(stderr, "Err: Timeout reached\n");
            return E_TIMEOUT;
        case E_NM_SRV:
            fprintf(stderr, "Err: \n");
            return E_NM_SRV;
        default:
            fprintf(stderr, "Err: Unknown error occurred\n");
            return 69;
    }
}
