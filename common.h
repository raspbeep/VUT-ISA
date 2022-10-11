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

struct DNSHeader {
    unsigned short id: 16;      // identification

    unsigned char qr: 1;        // query/response
    unsigned char opcode: 4;    // kind of query
    unsigned char aa: 1;        // authoritative answer
    unsigned char tc: 1;        // truncated
    unsigned char rd: 1;        // recursion desired
    unsigned char ra: 1;        // recursion available
    unsigned char z: 3;         // reserved
    unsigned char r_code: 4;    // response code

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

int get_packet(int sock, unsigned char *buffer, ssize_t *len);

int send_packet(int sock, unsigned char *buffer, int pos);

int open_file(const char *path, const char *read_mode, FILE **fptr);