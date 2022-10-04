/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_sender.c
 *
 * @brief
 */

#include "errors.h"
#include "dyn_string.h"
#include <stdio.h>
#include <string.h>
#include "stdbool.h"
#include <unistd.h>
#include <stdlib.h>

#include <netinet/in.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#define IP_ADDR "0.0.0.0"
#define PORT 53
#define BUFFER 1024
#define DNS_SIZE 512

struct InputArgs {
    // base domain for all communications
    char *base_host;
    // explicit remote DNS server
    char *upstream_dns_ip;
    // output file path on destination server
    char *dst_filepath;
    // if unspecified read from STDIN
    char *src_filepath;
};

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

int handle_error(const int err_n) {
    switch (err_n) {
        case E_INT:
            // print message
            return -2;
        case E_NUM_ARGS:
            fprintf(stderr, "Insufficient number of arguments\n");
            // invalid number of parameters
            return E_NUM_ARGS;
        case E_INV_ARGS:
            // invalid arguments
            return E_INV_ARGS;
        default:
            // print message
            return -3;
    }
}

void print_help() {
    printf( "Usage: ./dns_sender [-u UPSTREAM_DNS_IP] BASE_HOST DST_FILEPATH [SRC_FILEPATH]\n"
            "   UPSTREAM_DNS_IP -   Optional IP to DNS server, which requests are sent to(e.g. 127.0.0.1)\n"
            "   BASE_HOST       -   Required queried host to concatenate with sent data(e.g. example.com)\n"
            "   DST_FILEPATH    -   Required destination file name of transferred data(file.txt)\n"
            "   SRC_FILEPATH    -   Optional path to source file read in binary mode\n\n"
    );
}

int parse_args(int argc, char *argv[], struct InputArgs* args) {
    if (argc < 2 || argc > 7) {
        handle_error(E_NUM_ARGS);
        print_help();
        return E_NUM_ARGS;
    }

    // clear the struct values
    memset(args, 0, sizeof(struct InputArgs));

    int positional_arg_counter = 0;
    bool u_flag = false;

    for (size_t i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            if (argc != 2) return handle_error(E_INV_ARGS);
            print_help();
            return EXIT_H;
        }

        if (!strcmp(argv[i], "-u")) {
            if(u_flag) return handle_error(E_RE_U_ARGS);
            args->upstream_dns_ip = argv[++i];
            u_flag = true;
            continue;
        }

        if (!positional_arg_counter) {
            args->base_host = argv[i];
            positional_arg_counter++;
            continue;
        } else if (positional_arg_counter == 1) {
            args->dst_filepath = argv[i];
            positional_arg_counter++;
            continue;
        } else if (positional_arg_counter == 2){
            args->src_filepath = argv[i];
            continue;
        } else {
            return handle_error(E_POS_ARG);
        }
    }

    // no positional arguments were found
    if (positional_arg_counter < 1) {
        return handle_error(E_POS_ARG);
    }
    return EXIT_OK;
}


int open_file(const char *path, const char *read_mode, FILE **fptr) {
    *fptr = fopen(path, read_mode);
    if (*fptr == NULL) return E_OPEN_FILE;
    return EXIT_OK;
}


int read_src(char *src_filepath, string_t *buffer) {
    // initialize file descriptor to 0(stdin)
    FILE *fptr = 0;
    int c;
    // initialize empty string
    if (str_create_empty(buffer)) return E_INT;

    if (src_filepath) {
        // check reading permission
        if (access(src_filepath, R_OK)) {
            return E_RD_PERM;
        }
        // get file descriptor (only for binary reading)
        if (open_file(src_filepath, "rb", &fptr)) {
            return E_OPEN_FILE;
        }

        // read binary file
        c = fgetc(fptr);
        while (c != EOF) {
            if (str_append_char(buffer, (char)c)) {
                return E_INT;
            }
            c = fgetc(fptr);
        }
        // occurred an error reading character
        if (!feof(fptr)) {
            return E_RD_FILE;
        }
        return EXIT_OK;
    }

    read(0, &c, 1);
    while(c == 1) {
        if (str_append_char(buffer, (char)c)) return E_INT;
        read(0, &c, 1);
    }
    if (c == EOF) return EXIT_OK;
    return E_RD_FILE;
}


// KEEP FOR WRITING DATA ON RECEIVER SERVER
//int open_file_for_writing(const char *path, int *fd) {
//    // check writing permission
//    if (access(path, W_OK)) {
//        return E_WR_PERM;
//    }
//
//    // if the file at specified `path` does not exist, create it
//    int oflag = O_WRONLY | O_CREAT | O_EXCL;
//    return open_file(path, oflag, fd);
//}

void construct_dns_header(struct DNSHeader *header, unsigned int id) {
    // 16b aligned fields
    header->id = (unsigned short) htons(id); // TODO set correct ID

    header->qr = 0;                // query
    header->opcode = 0;            // standard query
    header->aa = 0;                // not authoritative
    header->tc = 0;                // not truncated
    header->rd = 0;                // no recursion
    header->ra = 0;                // no recursion
    header->z = 0;
    header->r_code = 0;            // no error

    header->q_count = htons(1);    // TODO: set correct number of questions
    header->ans_count = 0;
    header->ns_count = 0;
    header->ar_count = 0;
}

int dns_packet() {
    int sock;
    long i;
    struct sockaddr_in server, from;
    socklen_t len, from_len;
    unsigned int lock = 0;

    unsigned char buffer[DNS_SIZE];
    unsigned char *q_name;
    // clear buffer
    memset(buffer, 0, sizeof(buffer));
    memset(&server, 0, sizeof(server));

    server.sin_family = AF_INET;

    server.sin_addr.s_addr = inet_addr(IP_ADDR);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

    // initialize pointer to dns header
    struct DNSHeader *dns = NULL;

    // set pointer of dns header to the beginning of buffer
    dns = (struct DNSHeader *)&buffer;

    construct_dns_header(dns, getpid());
    // move lock in buffer
    lock += sizeof(struct DNSHeader);


    char n[15] = "www.google.com\0";
    string_t name;
    str_create_empty(&name);
    str_append_string(&name, n);

    string_t formatted;
    str_create_empty(&formatted);

    str_label_format(&name, &formatted);

    // set q_name pointer to a correct position in buffer
    q_name = (unsigned char*)&buffer[lock];
    str_copy_to_buffer(&formatted, q_name);
    lock += formatted.length + 1;

    struct Question *q_info = NULL;
    //  || DNS header || QNAME | QTYPE | QCLASS ||
    q_info = (struct Question*)&buffer[lock];
    q_info->q_type = htons(1);  // a record
    q_info->q_class = htons(1); // internet

    // create datagram socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        // TODO: handle this one
        return -1;
    }

    // connect to server
    if(connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        // TODO: handle this one
        return -1;
    }

    unsigned long length_of_buffer = sizeof(struct DNSHeader) + (formatted.length+1) + sizeof(struct Question);

    if (send(sock, buffer, length_of_buffer, 0) != length_of_buffer) {
        // TODO: handle this one
        return -1;
    }

    if (getsockname(sock, (struct sockaddr *) &from, &len)) {
        // TODO: handle this one
        return -1;
    }

    printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n",inet_ntoa(from.sin_addr), ntohs(from.sin_port), from.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);

    if ((i = recv(sock,buffer, BUFFER,0)) == -1) {
        // TODO: handle this one
        return -1;
    }

    if (getpeername(sock, (struct sockaddr *)&from, &from_len) != 0) {
        // TODO: handle this one
        return -1;
    }

    printf("* UDP packet received from %s, port %d\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port));
    printf("%d %s\n", (int)i, buffer);

    return 0;
}


int main(int argc, char *argv[]) {
    int result;

    // parse and store input arguments
    struct InputArgs args;
    result = parse_args(argc, argv, &args);
    // return 0 if `--help`
    if (result == EXIT_H) return EXIT_OK;
    if (result) return result;

    // read input and load into buffer
    string_t buffer;
    result = read_src(args.src_filepath, &buffer);
    if (result) return result;


    // split file into chunks
    // generate partial checksums
    // generate total checksum
    // generate DNS packages
    dns_packet();

    printf("%lu", sizeof(struct DNSHeader));

    printf("base host: %s\n", args.base_host);
    printf("upstream dns ip: %s\n", args.upstream_dns_ip);
    printf("dst filepath: %s\n", args.dst_filepath);
    printf("src filepath: %s\n", args.src_filepath);

    return 0;
}
