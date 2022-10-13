/**
 *
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file common.h
 *
 * @brief
 */

#pragma once
#include <arpa/inet.h>
#include <stdio.h>
#define DNS_PORT 53
#define DNS_SIZE 512
#define QNAME_SIZE 255
// two bits out of eight are reserved for reference distinction
#define LABEL_SIZE 63
#define TIMEOUT_S 3
#define QUESTION 0
#define ANSWER 1
#define NXDOMAIN 3

struct DNSHeader {
    unsigned short id: 16;      // identification

    unsigned char rd: 1;        // recursion desired
    unsigned char tc: 1;        // truncated
    unsigned char aa: 1;        // authoritative answer
    unsigned char opcode: 4;    // kind of query
    unsigned char qr: 1;        // query/response

    unsigned char r_code: 4;    // response code
    unsigned char cd: 1;        // authenticated data
    unsigned char ad: 1;        // checking disabled
    unsigned char z: 1;         // reserved

    unsigned char ra: 1;        // recursion available

    unsigned short q_count;     // 16b question count
    unsigned short ans_count;   // 16b answer count
    unsigned short ns_count;    // 16b nameserver RRS count
    unsigned short ar_count;    // 16b additional RRs count
};

struct Question {
    unsigned short q_type;      // 16b TYPE code field
    unsigned short q_class;     // 16b class of the query
};

void construct_dns_question(unsigned char *buffer);

void construct_dns_header(unsigned char *buffer, unsigned int id, uint16_t n_questions);

int get_packet(int sock, struct sockaddr_in *addr, unsigned char *buffer, ssize_t *rec_len, socklen_t *addr_len);

int send_packet(int sock, struct sockaddr_in *addr, unsigned char *buffer, int pos);

int send_and_wait(int sock_fd, struct sockaddr_in *addr, unsigned char *buffer,
        int pos, ssize_t *rec_len, socklen_t *addr_len, int id);

int open_file(const char *path, const char *read_mode, FILE **fptr);

int set_timeout(int sock_fd);

int unset_timeout(int sock_fd);

int handle_error(int err_n);