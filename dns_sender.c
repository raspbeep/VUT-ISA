/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_sender.c
 *
 * @brief
 */

#include <stdio.h>
#include <string.h>
#include "stdbool.h"
#include <unistd.h>
#include <stdlib.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "errors.h"
#include "common.h"
#include "dyn_string.h"
#include "dns_sender_events.h"

struct InputArgs {
    // base domain for all communication
    char *base_host;
    // in a correct format e.g. `.example.com.`
    string_t checked_base_host;
    // in dns format, e.g. `7example3com0`
    string_t formatted_base_host_string;
    // explicit remote DNS server
    char *upstream_dns_ip;
    // output file path on destination server
    char *dst_filepath;
    // if unspecified read from STDIN
    char *src_filepath;
} args;
bool u_flag = false;
struct sockaddr_in receiver_addr;
socklen_t addr_len;
int sock_fd;
unsigned long total_len = 0;
int TIMEOUT_EN = 1;

void print_help() {
    printf( "Usage: ./dns_sender [-u UPSTREAM_DNS_IP] BASE_HOST DST_FILEPATH [SRC_FILEPATH]\n"
            "   UPSTREAM_DNS_IP -   Optional IP to DNS server, which requests are sent to(e.g. 127.0.0.1)\n"
            "   BASE_HOST       -   Required queried host to concatenate with sent data(e.g. example.com)\n"
            "   DST_FILEPATH    -   Required destination file name of transferred data(file.txt)\n"
            "   SRC_FILEPATH    -   Optional path to source file read in binary mode\n\n"
    );
}

int check_base_host(string_t *base_host) {
    string_t dns_formatted_host;
    if (str_create_empty(&dns_formatted_host)) return E_INT;
    if (str_base_host_label_format(base_host, &dns_formatted_host)) return E_INT;

    // +1 for zero length octet at the end
    // +2 for at least on data byte(label length + one byte of data)
    // >=255 to leave at least one char for the actual data
    if (dns_formatted_host.length + 1 + 2 >= 255) {
        return E_HOST_LEN;
    }
    str_free(&dns_formatted_host);

    unsigned long count = 0;
    // check label length
    // +1 to check until the `\0` at the end
    unsigned char c;
    for (int i = 0; i < base_host->length + 1; i++) {
        c = *(base_host->ptr + i);
        if (c == '.' || c == '\0') {
            if (!count) continue;
            // rfc1035 2.3.4
            if (count > 63) {
                return E_HOST_LEN;
            }
            count = 0;
        } else {
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '-' || c == '.')) {
                return E_HOST_INV_CHAR;
            }
            count++;
        }
    }
    return EXIT_OK;
}

int format_base_host_string() {
    if (str_create_empty(&args.checked_base_host)) return E_INT;

    if (!args.base_host) return E_INT;
    // append dot at the beginning
    if (*args.base_host != '.') {
        if (str_append_char(&args.checked_base_host, '.')) return E_INT;
    }
    if (str_append_string(&args.checked_base_host, args.base_host)) return E_INT;
    if (check_base_host(&args.checked_base_host)) return E_INT;
    // save it into a global variable
    if (str_create_empty(&args.formatted_base_host_string)) return E_INT;
    // transform base host into DNS format
    if (str_base_host_label_format(&args.checked_base_host, &args.formatted_base_host_string)) return E_INT;
    return EXIT_OK;
}

int find_ip_version(const char *src) {
    char buf[64];
    if (inet_pton(AF_INET, src, buf)) {
        return 4;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return 6;
    }
    return -1;
}

int scan_resolv_conf() {
    int number_of_ips = 0;
    FILE *fd;
    open_file("/etc/resolv.conf", "r", &fd);
    char line_buffer[512] = {0};
    char ip_buffer[64] = {0};

    while(fgets(line_buffer, 512, fd)) {
        if (sscanf(line_buffer, "nameserver %s\n", ip_buffer)) {
            if (find_ip_version(ip_buffer) == 4) {
                number_of_ips += 1;
                args.upstream_dns_ip = malloc(sizeof(char) * strlen(ip_buffer) + 1);
                if (!args.upstream_dns_ip) {
                    return E_INT;
                }
                memset(args.upstream_dns_ip, 0, strlen(ip_buffer) + 1);
                strcpy(args.upstream_dns_ip, ip_buffer);
                break;
            }
        }
        for (int i = 0; i < 512; i++) {
            if (i < 64) {
                ip_buffer[i] = 0;
            }
            line_buffer[i] = 0;
        }
    }
    if (!number_of_ips) {
        return E_NM_SRV;
    }
    fclose(fd);
    return 0;
}

int parse_args(int argc, char *argv[]) {
    if (argc < 2 || argc > 6) {
        handle_error(E_NUM_ARGS);
        print_help();
        return E_NUM_ARGS;
    }

    // clear the struct values
    memset(&args, 0, sizeof(struct InputArgs));

    int positional_arg_counter = 0;

    for (size_t i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            if (argc != 2) return handle_error(E_INV_ARGS);
            print_help();
            return EXIT_HELP;
        }

        if (!strcmp(argv[i], "-u")) {
            if(u_flag) return handle_error(E_RE_U_ARGS);
            args.upstream_dns_ip = argv[++i];
            u_flag = true;
            continue;
        }

        if (!positional_arg_counter) {
            args.base_host = argv[i];
            positional_arg_counter++;
            continue;
        } else if (positional_arg_counter == 1) {
            args.dst_filepath = argv[i];
            positional_arg_counter++;
            continue;
        } else if (positional_arg_counter == 2){
            args.src_filepath = argv[i];
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
    // checks validity of provided base host and converts it into DNS format
    if (format_base_host_string()) return E_INT;
    // upstream DNS server was not given, try to find one in /etc/resolv.conf
    if (!u_flag) {
        if (scan_resolv_conf()) return E_NM_SRV;
    }
    return EXIT_OK;
}

int read_src(string_t *buffer) {
    FILE *fptr = 0;
    int c;

    if (args.src_filepath) {
        if (open_file(args.src_filepath, "rb", &fptr)) {
            return E_OPEN_FILE;
        }
        // read binary file
        c = fgetc(fptr);
        while (c != EOF) {
            if (str_append_char(buffer, (char)c)) return E_INT;
            c = fgetc(fptr);
        }
        // occurred an error reading character
        if (!feof(fptr)) return E_RD_FILE;
        total_len = buffer->length;
        return EXIT_OK;
    }

    ssize_t res;
    while((res = read(0, &c, 1)) == 1) {
        if (str_append_char(buffer, (char)c)) return E_INT;
    }
    if (res == 0) return EXIT_OK;
    // for valgrind
    fflush(fptr);
    fclose(fptr);
    total_len = buffer->length;
    return E_RD_FILE;
}

void free_chunks(string_t **chunks, unsigned long n_chunks) {
    for (unsigned long i = 0; i < n_chunks; i++) {
        string_t *current = (string_t *)(*chunks + (i));
        str_free(current);
    }
    free(*chunks);
}

int split_into_chunks(string_t *data, string_t **chunks, unsigned long *n_chunks) {
    // available length of data in one QNAME = DATA+BASE_HOST
    int available_data_length = QNAME_SIZE - args.formatted_base_host_string.length;
    *chunks = malloc(sizeof(string_t));
    if (str_create_empty(*chunks)) return E_INT;
    if (!*chunks) return E_INT;

    int capacity_left;
    unsigned long count = 0;
    bool first;
    char c;
    int current_count;
    unsigned long chunk_count = 0;

    // for calling interface function
    string_t chunk_no_dns_format;

    while (count != data->length) {
        if (str_create_empty(&chunk_no_dns_format)) return E_INT;
        current_count = 0;
        first = true;
        // copy of available data length
         capacity_left = available_data_length;
        // current chunk
        string_t *current = (string_t *)(*chunks + chunk_count);
        // until chunk is full or any data is left
        while(capacity_left && count != data->length) {
            // insert length octet at the beginning or after 63 chars of data
            if (first || current_count == 64) {
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
                if (str_append_char(current, c)) return E_INT;
                // for calling interface function
                if (!first) {
                    if (str_append_char(&chunk_no_dns_format, '.')) return E_INT;
                }
                capacity_left--;
                current_count++;
                first = false;
            } else {
                if (str_append_char(current, data->ptr[count])) return E_INT;
                // for calling interface function
                if (str_append_char(&chunk_no_dns_format, data->ptr[count])) return E_INT;
                current_count++;
                capacity_left--;
                count++;
            }
        }
        // concatenate with base host
        if (str_append_strings(current, &args.formatted_base_host_string)) return E_INT;
        // concatenate with base host in dot format
        if (str_append_strings(&chunk_no_dns_format, &args.checked_base_host)) return E_INT;
        // remove last dot
        *(chunk_no_dns_format.ptr + chunk_no_dns_format.length - 1) = '\0';
        dns_sender__on_chunk_encoded(args.src_filepath, (int)chunk_count + 1,
                                     chunk_no_dns_format.ptr);

        // a new chunk will be needed
        if (count != data->length) {
            chunk_count++;
            string_t *ptr;
            // +1 because chunk_count is counted from 0
            ptr = realloc(*chunks, (chunk_count + 1) * sizeof(string_t));
            if (!ptr) return E_INT;
            *chunks = ptr;
            if (str_create_empty((string_t *)(*chunks + (chunk_count)))) return E_INT;
            str_free(&chunk_no_dns_format);
            if (str_create_empty(&chunk_no_dns_format)) return E_INT;
        }
    }
    *n_chunks = chunk_count + 1;
    return EXIT_OK;
}

int init_connection() {
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = inet_addr(args.upstream_dns_ip);
    receiver_addr.sin_port = htons(/*DNS_PORT*/1645);

    // create datagram socket
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return E_SOCK_CRT;
    }

    return EXIT_OK;
}

int send_first_info_packet(unsigned long n_chunks, unsigned char *buffer, int *pos) {
    // format of first packet
    memset(buffer, 0, DNS_SIZE);
    int id = 0;
    construct_dns_header((buffer), id, 1);
    *pos += sizeof(struct DNSHeader);

    char b[LABEL_SIZE + 1] = {0};
    sprintf(b, "%lu", n_chunks);
    if (strlen(b) > 63) {
        return E_INT;
    }
    *(buffer + *pos) = (char)strlen(b);
    *pos += 1;
    sprintf((char *)(buffer + *pos), "%lu", n_chunks);
    *pos += (int)strlen(b);

    // append dst_filepath in the form of `/name[.file_extension]`
    int count = 0;
    char *c = &args.dst_filepath[0];
    while (*c != '.' && *c != '\0') {
        c++;
        count ++;
    }
    *(buffer + *pos) = count;
    *pos += 1;
    for (int i = 0; i < strlen(args.dst_filepath); i++) {
        if (args.dst_filepath[i] == '.') {
            c = &args.dst_filepath[i+1];
            count = 0;
            while (*c != '.' && *c != '\0') {
                c++;
                count ++;
            }
            *(buffer + *pos) = count;
        } else {
            *(buffer + *pos) = args.dst_filepath[i];
        }
        *pos += 1;
    }

    // append base host domain from argument
    for (int i = 0; i < args.formatted_base_host_string.length; i++) {
        *(buffer + *pos + i) = *(args.formatted_base_host_string.ptr + i);
    }
    *pos += (int)args.checked_base_host.length;

    construct_dns_question(buffer + *pos);
    *pos += sizeof(struct Question);

    ssize_t rec_len;
    int res;
    if ((res = send_and_wait(sock_fd, &receiver_addr, buffer, *pos, &rec_len,
                             &addr_len, id)) != 0) {
        return res;
    }
    return EXIT_OK;
}

int send_packets(string_t **chunks, unsigned long n_chunks) {
    int pos = 0;
    unsigned char buffer[DNS_SIZE];
    ssize_t rec_len;

    if (init_connection()) return E_INIT_CONN;
    if (TIMEOUT_EN) {
        if (set_timeout(sock_fd)) return E_INT;
    }

    dns_sender__on_transfer_init((struct in_addr *)&receiver_addr.sin_addr);
    if (send_first_info_packet(n_chunks, buffer, &pos)) return E_PKT_SEND;

    for (unsigned int chunk_n = 0; chunk_n < n_chunks; chunk_n++) {
        //  || DNS header || QNAME | QTYPE | QCLASS ||
        pos = 0;
        int chunk_id = (int)(chunk_n + 1)%(1<<16);
        memset(buffer, 0, sizeof(buffer));
        // create header and shift `pos`
        construct_dns_header(buffer, chunk_n + 1, 1);
        pos += sizeof(struct DNSHeader);

        // copy data into buffer and shift `pos`
        string_t *current_chunk = (string_t *)(*chunks + chunk_n);
        // copy chunk data to buffer
        str_copy_to_buffer(current_chunk, buffer + pos);
        // +1 for null byte at the end of QNAME
        pos += (int)(*chunks + chunk_n)->length;

        // create question info and shift `pos`
        construct_dns_question(buffer + pos);
        pos += sizeof(struct Question);

        // calling interface function
        dns_sender__on_chunk_sent((struct in_addr *)&receiver_addr.sin_addr,
                args.dst_filepath, chunk_id, (int)current_chunk->length);
        int res;
        if ((res = send_and_wait(sock_fd, &receiver_addr, buffer, pos, &rec_len,
                                 &addr_len, chunk_id))) {
            free_chunks(chunks, n_chunks);
            return res;
        }
    }
    dns_sender__on_transfer_completed(args.dst_filepath, (int)total_len);
    free_chunks(chunks, n_chunks);
    return EXIT_OK;
}

int main(int argc, char *argv[]) {
    int result;

    // parse and store input arguments
    result = parse_args(argc, argv);
    // return 0 if `--help`
    if (result == EXIT_HELP) return EXIT_OK;
    if (result) return result;

    // read input and load into buffer
    string_t buffer;
    if (str_create_empty(&buffer)) return E_INT;
    result = read_src(&buffer);
    if (result) return result;

    string_t encoded_string;
    printf("Length binary: %lu\n", buffer.length);
    str_base16_encode(&buffer, &encoded_string);
    printf("Length base16: %lu\n", encoded_string.length);
    string_t *chunks = NULL;
    unsigned long n_chunks;
    result = split_into_chunks(&encoded_string, &chunks, &n_chunks);
    if (result == EXIT_OK) {
        if ((result = send_packets(&chunks, n_chunks)) != EXIT_OK) {
            str_free(&args.checked_base_host);
            str_free(&args.formatted_base_host_string);
            if (!u_flag) {
                free(args.upstream_dns_ip);
            }
            close(sock_fd);
            return result;
        }
    }

    str_free(&encoded_string);
    str_free(&buffer);
    str_free(&args.checked_base_host);
    str_free(&args.formatted_base_host_string);
    if (!u_flag) {
        free(args.upstream_dns_ip);
    }
    close(sock_fd);

    return EXIT_OK;
}
