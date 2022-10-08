/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_sender.c
 *
 * @brief
 */



#pragma once
#include <arpa/inet.h>
#define DNS_PORT 53
#define DNS_SIZE 512
#define QNAME_SIZE 255
// two bytes out of eight are reserved for reference distinction
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

void construct_dns_header(struct DNSHeader *header, unsigned int id) {
    // 16b aligned fields
    header->id = (unsigned short) htons(id);

    header->qr = 0;                 // query
    header->opcode = 0;             // standard query
    header->aa = 0;                 // not authoritative
    header->tc = 0;                 // not truncated
    header->rd = 0;                 // no recursion
    header->ra = 0;                 // no recursion
    header->z = 0;                  // no special use
    header->r_code = 0;             // no error

    header->q_count = htons(1);     // 1 question
    header->ans_count = 0;          // 0 answers
    header->ns_count = 0;           // 0 nameserver RRs
    header->ar_count = 0;           // 0 additional RRs
}


// "?gbhdgeggghgigkglgmgbhdgeggghgigkglgmgbhdgeggghgigkglgmgbhdgegg?ghgigkglgmgbhdgeggghgigkglgmgbhdgeggghgigkglgmakgbhdgeggghgigk?glgmgbhdgeggghgigkglgmgbhdgeggghgigkglgmgbhdgeggghgigkglgmgbhd5geggghgigkglgmgbhdgeggghgigkglgmakgbhdgeggghgigkglgm.example.com"