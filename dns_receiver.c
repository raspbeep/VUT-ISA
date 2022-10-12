/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_sender.c
 *
 * @brief
 */


#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "common.h"
#include "errors.h"
#include "dyn_string.h"

struct InputArgs {
    // base domain for all communications
    char *base_host;
    // output file path on destination server
    char *dst_filepath;
};

int sock_fd;
struct sockaddr_in serv_addr, client_addr;
socklen_t addr_len;

void print_help() {
    printf( "Usage: ./dns_receiver BASE_HOST DST_FILEPATH\n"
            "   BASE_HOST       -   Required queried host to concatenate with sent data(e.g. example.com)\n"
            "   DST_FILEPATH    -   Required destination of transferred data (e.g. ./received_data/),\n"
            "                       resulting filename is determined by sender.\n\n"
    );
}

int parse_args(int argc, char *argv[], struct InputArgs* args) {
    if (argc < 3) {
        handle_error(E_NUM_ARGS);
        print_help();
        return E_NUM_ARGS;
    }

    // clear the struct values
    memset(args, 0, sizeof(struct InputArgs));
    int positional_arg_counter = 0;

    for (size_t i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            if (i != 1) return handle_error(E_INV_ARGS);
            print_help();
            return EXIT_HELP;
        }
        if (!positional_arg_counter) {
            args->base_host = argv[i];
            positional_arg_counter++;
            continue;
        } else if (positional_arg_counter == 1) {
            args->dst_filepath = argv[i];
            positional_arg_counter++;
            continue;
        } else {
            return handle_error(E_POS_ARG);
        }
    }
    // insufficient number of positional arguments were found
    // at least too are required
    if (positional_arg_counter != 2) {
        return handle_error(E_POS_ARG);
    }
    return EXIT_OK;
}

int check_dst_filepath(char *dst_filepath, string_t *filepath_string) {
    if (str_append_string(filepath_string, dst_filepath)) return E_INT;

    if (filepath_string->ptr[filepath_string->length - 1] != '/') {
        if (str_append_char(filepath_string, '/')) return E_INT;
    }

    // folder is not writeable
    // need this check for stat
    // TODO: do I need access to all subdirs and files in them?
    if (access(filepath_string->ptr, W_OK)) return E_INT;

    // check if it is a folder
    struct stat stat_res;
    if (stat(filepath_string->ptr, &stat_res) != 0)
        return 0;
    if (!S_ISDIR(stat_res.st_mode)) {
        // TODO: not a directory error
        return E_INT;
    }
    return EXIT_OK;
}

int get_buffer_data(unsigned char *buffer, string_t *data, char *base_host) {
    unsigned long label_length_octet;

    unsigned long count = 0, pos;

    // TODO: implement in a better way
    string_t base_host_string;
    str_create_empty(&base_host_string);
    str_append_string(&base_host_string, base_host);
    // +1 for null byte
    *(buffer + strlen((char *)buffer) - (base_host_string.length)) = '\0';
    str_free(&base_host_string);

    label_length_octet = (unsigned char)*buffer;
    while (label_length_octet != '\0') {
        label_length_octet = (unsigned char)*(buffer+count);
        count++;
        pos = count;
        for (unsigned int i = count; i < pos + label_length_octet; i++) {
            if (str_append_char(data, *((char *)buffer + count))) return E_INT;
            count++;
        }
    }
    return EXIT_OK;
}

int send_ack_response(unsigned char *buffer, unsigned int id, socklen_t length) {
    memset(buffer, 0, DNS_SIZE);
    construct_dns_header((unsigned char *)buffer, id, 0);
//    struct DNSHeader *dns_header = (struct DNSHeader *)buffer;
//    dns_header->ans_count = htons(1);
    int l = sizeof(struct DNSHeader);

    if (send_packet(sock_fd, &client_addr, buffer, l)) return E_PKT_SEND;
    return EXIT_OK;
}

int get_info_from_first_packet(unsigned char *buffer, long unsigned *chunk_n, char **dst_filepath) {
    char *ptr = (char *)buffer;
    char chunk_n_buffer[LABEL_SIZE + 1] = {0};
    char chunk_n_length = *ptr;
    ptr++;
    for (int i = 0; i < chunk_n_length; i++) {
        chunk_n_buffer[i] = ptr[i];
    }
    ptr += chunk_n_length;
    *chunk_n = strtol(chunk_n_buffer, NULL, 10);

    char filepath_length_1 = *ptr;
    ptr++;
    // two labels + dot + null byte
    char dst_filepath_buffer[(LABEL_SIZE * 2) + 2] = {0};
    for (int i = 0; i < filepath_length_1; i++) {
        dst_filepath_buffer[i] = ptr[i];
    }
    ptr += filepath_length_1;
    dst_filepath_buffer[filepath_length_1] = '.';

    char filepath_length_2 = *ptr;
    for (int i = 0; i < filepath_length_2; i++) {
        dst_filepath_buffer[filepath_length_1 + i + 1] = ptr[i + 1];
    }

    *dst_filepath = malloc(sizeof(char) * strlen(dst_filepath_buffer));
    if (!*dst_filepath) return E_INT;
    strcpy(*dst_filepath, dst_filepath_buffer);

    return EXIT_OK;
}

int init_connection() {
    memset(&serv_addr, 0, sizeof(serv_addr));
    memset(&client_addr, 0, sizeof(client_addr));

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(DNS_PORT);

    printf("opening UDP socket(...)\n");
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) return E_SOCK_CRT;

    //    struct timeval timeout;
    //    timeout.tv_sec = 1;
    //    timeout.tv_usec = 1;
    //    if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
    //        return E_TIMEOUT;
    //    }

    printf("binding with the port %d (%d)\n",ntohs(serv_addr.sin_port), serv_addr.sin_port);

    if (bind(sock_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == -1) return E_BIND;
    addr_len = sizeof(client_addr);
    return EXIT_OK;
}

int main(int argc, char *argv[]) {
    unsigned char buffer[DNS_SIZE];
    char *dst_file_path = NULL;

    struct InputArgs args;
    int res;
    if ((res = parse_args(argc, argv, &args) > EXIT_OK)) {
        if (res == EXIT_HELP) {
            return EXIT_OK;
        }
        return E_INV_ARGS;
    }
    printf("Starting\n");
    if (init_connection()) return E_INIT_CONN;
    while (1) {
        string_t dst_filepath_string;
        if (str_create_empty(&dst_filepath_string)) return E_INT;
        // check filepath, appends `/` at the end if necessary
        // checks dir and is writeable and
        if (check_dst_filepath(args.dst_filepath, &dst_filepath_string)) {
            return handle_error(E_INT);
        }

        struct DNSHeader *dns_header = NULL;
        string_t data;
        if (str_create_empty(&data)) return E_INT;

        string_t all_encoded_data;
        str_create_empty(&all_encoded_data);

        ssize_t rec_len;
        if (get_packet(sock_fd, &client_addr, buffer, &rec_len, &addr_len)) return E_INT;

        unsigned long n_chunks;
        get_info_from_first_packet(buffer + sizeof(struct DNSHeader), &n_chunks, &dst_file_path);
        if (send_ack_response(buffer, 0, addr_len)) return E_INT;

        for (int i = 0; i < n_chunks; i++) {
            if (get_packet(sock_fd, &client_addr, buffer, &rec_len, &addr_len)) return E_INT;
            dns_header = (struct DNSHeader *)&buffer;
            unsigned long pos = sizeof(struct DNSHeader);
            unsigned id = ntohs(dns_header->id);

            // remove label length octets and remove base host suffix
            if (get_buffer_data(buffer + pos, &data, args.base_host)) return E_INT;
            str_append_strings(&all_encoded_data, &data);

            str_free(&data);
            if (str_create_empty(&data)) return E_INT;

            if (send_ack_response(buffer, id, addr_len)) return E_INT;
        }
        str_free(&data);

        // decode all data
        string_t all_data;
        if (str_create_empty(&all_data)) return E_INT;
        str_base16_decode(&all_encoded_data, &all_data);
        printf("Length decoded: %lu\n", all_data.length);

        if (str_append_string(&dst_filepath_string, dst_file_path)) return E_INT;
        FILE *ptr;
        if (open_file(dst_filepath_string.ptr, "wb", &ptr)) return E_OPEN_FILE;
        printf("Writing to file\n");
        fwrite(all_data.ptr, 1, all_data.length, ptr);
        fclose(ptr);
        str_free(&all_data);
    }


    printf("closing socket\n");
    close(sock_fd);

    return 0;
}
