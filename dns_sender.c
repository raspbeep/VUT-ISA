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
#include "dns.h"
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

    // insufficient number of positional arguments were found
    // at least too are required
    if (positional_arg_counter <= 1) {
        return handle_error(E_POS_ARG);
    }
    return EXIT_OK;
}


int open_file(const char *path, const char *read_mode, FILE **fptr) {
    *fptr = fopen(path, read_mode);
    if (*fptr == NULL) return E_OPEN_FILE;
    return EXIT_OK;
}

/**
 * Reads input data from filepath(if was given) or reads from STDIN
 * until EOF is found. Checks permission for reading file on filepath.
 * returns E_RD_PERM if permissions are insufficient for reading.
 *
 *
 * @param src_filepath data is read from this path
 * @param buffer for saving data, must be allocated and empty
 *
 * @returns Returns E_RD_PERM or E_OPEN_FILE if permissions are
 * insufficient for reading. E_RD_FILE is return when an error reading
 * input file occurred. Otherwise returns EXIT_OK(0).
 */
int read_src(char *src_filepath, string_t *buffer) {
    FILE *fptr = 0;
    int c;

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

    ssize_t res;
    while((res = read(0, &c, 1)) == 1) {
        if (str_append_char(buffer, (char)c)) return E_INT;
    }
    if (res == 0) return EXIT_OK;
    return E_RD_FILE;
}

/**
 * Checks the allowed length of base host. Name length must be shorter
 * than 63 bytes and the total length of DNS formatted base host must
 * be shorter than 252 (1 null byte and 2 bytes for data - length + char)
 * to leave space for the encoded data
 *
 *
 * @param base_host data is read from this path
 *
 * @returns E_HOST_LEN for invalid length, return EXIT_OK(0) otherwise
 */
int check_base_host_len(string_t *base_host) {
    string_t dns_formatted_host;
    if (str_create_empty(&dns_formatted_host)) return E_INT;
    if (str_base_host_label_format(base_host, &dns_formatted_host)) return E_INT;

    // +1 for zero length octet at the end
    // +2 for at least on data byte(label length + one byt of data)
    // >=255 to leave at least one char for the actual data
    if (dns_formatted_host.length + 1 + 2 >= 255) {
        return E_HOST_LEN;
    }
    str_free(&dns_formatted_host);

    unsigned long count = 0;
    // check label length
    // +1 to check until the `\0` at the end
    for (int i = 0; i < base_host->length + 1; i++) {
        if (*(base_host->ptr + i) == '.' || *(base_host->ptr + i) == '\0') {
            if (!count) continue;
            // rfc1035 2.3.4
            if (count > 63) {
                return E_HOST_LEN;
            }
            count = 0;
        } else {
            count++;
        }
    }
    return EXIT_OK;
}

/**
 *
 *
 *
 * @param base_host base host to appended in DNS format to each QNAME
 * @param data all data to send
 * @param chunks pointer to array of data chunks to send
 * @param n_chunks number of chunks(packets) to send
 *
 * @returns
 */
int split_into_chunks(char *base_host, string_t *data, string_t **chunks, unsigned long *n_chunks) {
    string_t base_host_string;
    if (str_create_empty(&base_host_string)) return E_INT;
    if (!base_host) return E_INT;

    // append dot at the beginning
    if (*base_host != '.') {
        if (str_append_char(&base_host_string, '.')) return E_INT;
    }
    if (str_append_string(&base_host_string, base_host)) return E_INT;
    if (check_base_host_len(&base_host_string)) return E_INT;

    string_t formatted_base_host_string;
    if (str_create_empty(&formatted_base_host_string)) return E_INT;
    // transform base host into DNS format
    if (str_base_host_label_format(&base_host_string, &formatted_base_host_string)) return E_INT;

    // available length of data in one QNAME = DATA+BASE_HOST+1
    // -1 for zero length octet
    int available_data_length = QNAME_SIZE - formatted_base_host_string.length;

    *chunks = malloc(sizeof(string_t));
    if (str_create_empty(*chunks)) return E_INT;
    if (!*chunks) return E_INT;

    int capacity_left;
    unsigned long count = 0;
    bool first;
    char c;
    int current_count;
    unsigned long chunk_count = 0;
    while (count != data->length) {
        current_count = 0;
        first = true;
        // copy of available data length
         capacity_left = available_data_length;
        // current chunk
        string_t *current = (string_t *)(*chunks + chunk_count);
        // until chunk is full or any data is left
        while(capacity_left && count != data->length) {
            if (first || current_count == 64) {
                printf("left: %lu\n", data->length - count);
                current_count = 0;
                // if total data left to copy is larger than current label size
                if (data->length - count >= LABEL_SIZE) {
                    if (LABEL_SIZE > capacity_left) {
                        // -1 to leave space for the `c` char itself
                        c = (char)(capacity_left - 1);
                    } else {
                        c = LABEL_SIZE;
                    }
                } else {
                    // length is shorter than 63
                    c = (char)(data->length-count);
                }
                str_append_char(current, c);
                capacity_left--;
                current_count++;

                first = false;
            } else {
                if (str_append_char(current, data->ptr[count])) return E_INT;
                current_count++;
                capacity_left--;
                count++;
            }
        }
        // concatenate with base host
        if (str_append_strings(current, &formatted_base_host_string)) return E_INT;

        // a new chunk will be needed
        if (count != data->length) {
            chunk_count++;
            string_t *ptr;
            // +1 because chunk_count is counted from 0
            ptr = realloc(*chunks, (chunk_count + 1) * sizeof(string_t));
            if (!ptr) return E_INT;
            *chunks = ptr;
            if (str_create_empty((string_t *)(*chunks + (chunk_count)))) return E_INT;
        }
    }
    *n_chunks = chunk_count + 1;
    str_free(&formatted_base_host_string);
    return EXIT_OK;
}

//int create_first_info_packet(char *buffer, unsigned long n_chunks) {
//
//
//
//}

int dns_packet(string_t **chunks, unsigned long n_chunks) {
    int sock;
    struct sockaddr_in server, from;
    socklen_t len, from_len;
    unsigned int pos = 0;
    unsigned char buffer[DNS_SIZE];
    // initialize pointer to dns header
    struct DNSHeader *dns_header = NULL;
    struct Question *q_info = NULL;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(IP_ADDR);
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);

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

    // clear buffer
    memset(buffer, 0, DNS_SIZE);
    dns_header = (struct DNSHeader *)&buffer;
    construct_dns_header(dns_header, 0);
    pos += sizeof(struct DNSHeader);

    sprintf((char *)(buffer+pos), "%lu\n", n_chunks);

    pos += strlen((char *)buffer+pos);
    q_info = (struct Question*)&buffer[pos];
    q_info->q_type = htons(1);  // a record
    q_info->q_class = htons(1); // internet

    pos += sizeof(struct Question);

    // printf("%s", (*chunks + chunk_n)->ptr);
    if (send(sock, buffer, pos, 0) != pos) {
        // TODO: handle this one
        return -1;
    }

//    if (getsockname(sock, (struct sockaddr *) &from, &len)) {
//        // TODO: handle this one
//        return -1;
//    }

    if ((recv(sock, buffer, DNS_SIZE, 0)) == -1) {
        // TODO: handle this one
        return -1;
    }

//    if (getpeername(sock, (struct sockaddr *)&from, &from_len) != 0) {
//        // TODO: handle this one
//        return -1;
//    }

    printf("n_chunks: %lu\n", n_chunks);
    for (unsigned int chunk_n = 0; chunk_n < n_chunks; chunk_n++) {
        //  || DNS header || QNAME | QTYPE | QCLASS ||
        // position in buffer
        pos = 0;
        // memset(&server, 0, sizeof(server));
        memset(buffer, 0, sizeof(buffer));

        // initialize pointer to dns header
        dns_header = NULL;
        // set pointer of dns header to the beginning of buffer
        dns_header = (struct DNSHeader *)&buffer;
        construct_dns_header(dns_header, chunk_n);
        pos += sizeof(struct DNSHeader);


        string_t *current_chunk =(string_t *)(*chunks + chunk_n);
        // copy chunk data to buffer
        str_copy_to_buffer(current_chunk, buffer + pos);

        // +1 for null byte at the end of QNAME
        pos += (*chunks + chunk_n)->length + 1;

        q_info = NULL;
        q_info = (struct Question*)&buffer[pos];
        q_info->q_type = htons(1);  // a record
        q_info->q_class = htons(1); // internet

        pos += sizeof(struct Question);

        if (send(sock, buffer, pos, 0) != pos) {
            // TODO: handle this one
            return -1;
        }

//        if (getsockname(sock, (struct sockaddr *) &from, &len)) {
//            // TODO: handle this one
//            return -1;
//        }

        if ((recv(sock, buffer, DNS_SIZE, 0)) == -1) {
            // TODO: handle this one
            return -1;
        }

//        if (getpeername(sock, (struct sockaddr *)&from, &from_len) != 0) {
//            // TODO: handle this one
//            return -1;
//        }
    }
    free(*chunks);

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
    if (str_create_empty(&buffer)) return E_INT;
    result = read_src(args.src_filepath, &buffer);
    if (result) return result;

    string_t encoded_string;
    str_create_empty(&encoded_string);
    printf("Length binary: %lu\n", buffer.length);
    str_base16_encode(&buffer, &encoded_string);
    printf("Length base16: %lu\n", encoded_string.length);
    string_t *chunks = NULL;
    unsigned long n_chunks;
    split_into_chunks(args.base_host, &encoded_string, &chunks, &n_chunks);

    dns_packet(&chunks, n_chunks);

    printf("base host: %s\n", args.base_host);
    printf("upstream dns ip: %s\n", args.upstream_dns_ip);
    printf("dst filepath: %s\n", args.dst_filepath);
    printf("src filepath: %s\n", args.src_filepath);

    return 0;
}
