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

    header->qr = QUERY;                         // query
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
        if (errno == EAGAIN) {
            return handle_error(E_TIMEOUT);
        } else {
            return handle_error(E_PKT_SEND);
        }
    }
    return EXIT_OK;
}

int get_packet(int sock, struct sockaddr_in *addr, unsigned char *buffer, ssize_t *rec_len, socklen_t *addr_len) {
    if ((*rec_len = recvfrom(sock, buffer, DNS_SIZE, 0, (struct sockaddr *)addr, addr_len)) <= 0) {
        if (errno == EAGAIN) {
            return handle_error(E_TIMEOUT);
        } else {
            return handle_error(E_PKT_REC);
        }
    }
    return EXIT_OK;
}

int get_packet_id(unsigned char *buffer) {
    struct DNSHeader *dns_header = (struct DNSHeader *)buffer;
    if (dns_header->r_code != NXDOMAIN) return -1;
    return ntohs(dns_header->id);
}

int send_and_wait(int sock_fd, struct sockaddr_in *addr, unsigned char *buffer,
        int pos, ssize_t *rec_len, socklen_t *addr_len, int id) {
    int res;
    // attempt to send 1
    res = send_packet(sock_fd, addr, buffer, pos);
    if (res == EXIT_OK) {
        // first send success
        // attempt to receive 1
        res = get_packet(sock_fd, addr, buffer, rec_len, addr_len);
        if (res == EXIT_OK && get_packet_id(buffer) == id) {
            // first receive success
            return EXIT_OK;
        } else if (res == E_TIMEOUT) {
            // first receive failed on timeout
            // attempt to receive 2
            res = get_packet(sock_fd, addr, buffer, rec_len, addr_len);
            if (res == EXIT_OK && get_packet_id(buffer) == id) {
                // second receive success
                return EXIT_OK;
            } else {
                // second receive fail
                return E_PKT_REC;
            }
        } else {
            // second receive failed on timeout
            return E_PKT_REC;
        }
    } else if (res == E_TIMEOUT) {
        // first send failed on timeout
        // attempt to send 2
        res = send_packet(sock_fd, addr, buffer, pos);
        if (res == EXIT_OK) {
            // second send success
            // attempt to receive 1
            res = get_packet(sock_fd, addr, buffer, rec_len, addr_len);
            if (res == EXIT_OK && get_packet_id(buffer) == id) {
                // first receive success
                return EXIT_OK;
            } else if (res == E_TIMEOUT) {
                // first receive failed on timeout
                // attempt to receive 2
                res = get_packet(sock_fd, addr, buffer, rec_len, addr_len);
                if (res == EXIT_OK && get_packet_id(buffer) == id) {
                    // second receive success
                    return EXIT_OK;
                } else {
                    // second receive fail
                    return E_PKT_REC;
                }
            } else {
                // second receive failed on timeout
                return E_PKT_REC;
            }
        }
    } else {
        // failed send because of error(not timeout)
        return E_PKT_SEND;
    }
    return EXIT_OK;
}

int set_timeout(int sock_fd) {
    struct timeval timeout = {TIMEOUT_S,0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return E_SET_TIMEOUT;
    }
    return EXIT_OK;
}

int unset_timeout(int sock_fd) {
    struct timeval timeout = {0,0};
    if (setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0 ||
        setsockopt(sock_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return E_SET_TIMEOUT;
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
        case E_NOT_DIR:
            fprintf(stderr, "Err: DST_FILEPATH is not a directory\n");
            return E_NOT_DIR;
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
            fprintf(stderr, "Err: Error sending packet\n");
            return E_PKT_SEND;
        case E_PKT_REC:
            fprintf(stderr, "Err: Error receiving packet\n");
            return E_PKT_REC;
        case E_INIT_CONN:
            fprintf(stderr, "Err: Error initializing connection\n");
            return E_INIT_CONN;
        case E_SOCK_CRT:
            fprintf(stderr, "Err: Failed to create socket\n");
            return E_SOCK_CRT;
        case E_BIND:
            fprintf(stderr, "Err: Error binding to socket\n");
            return E_BIND;
        case E_TIMEOUT:
            fprintf(stderr, "Err: Timeout reached\n");
            return E_TIMEOUT;
        case E_SET_TIMEOUT:
            fprintf(stderr, "Err: Setting timeout on socket failed\n");
            return E_SET_TIMEOUT;
        case E_NM_SRV:
            fprintf(stderr, "Err: Unable to get implicit namerserver from /etc/resolf.conf\n");
            return E_NM_SRV;
        default:
            fprintf(stderr, "Err: Unknown error occurred\n");
            return 69;
    }
}
