/**
 *
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file common.c
 *
 * @brief
 */

#include <stdio.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
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

int send_packet(int sock, unsigned char *buffer, int pos) {
    if (send(sock, buffer, pos, 0) != pos) {
        return E_PKT_SEND;
    }
    return EXIT_OK;
}

int get_packet(int sock, unsigned char *buffer, ssize_t *len) {
    if ((*len = recv(sock, buffer, DNS_SIZE, 0)) <= 0) {
        return E_PKT_REC;
    }
    return EXIT_OK;
}
