/**
 * dns_receiver
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_receiver.c
 *
 * @brief Server side of DNS tunneling application
 */

#include "dns_receiver.h"
// timeout for receiver
#define REC_TO_S 10

struct InputArgs {
    // base domain for all communications
    char *base_host;
    char *checked_base_host;
    // output folder on destination server
    char *dst_filepath;
    // complete output path, dst_filepath + file name from the first packet
    char *complete_dst_filepath;
} args;

int sock_fd;
struct sockaddr_in receiver_addr, sender_addr;
socklen_t addr_len;
FILE *out_ptr;
// enable timeouts for sending and receiving packets
int timeout = 1;
// enable calling interface functions
int interface = 1;
// enable debug messages
int debug = 0;

void print_help() {
    printf( "Usage: ./dns_receiver BASE_HOST DST_FILEPATH\n"
            "   BASE_HOST       -   Required queried host to concatenate with sent data(e.g. example.com)\n"
            "   DST_FILEPATH    -   Required destination of transferred data (e.g. ./received_data/),\n"
            "                       resulting filename is determined by sender.\n\n"
    );
}

int check_base_host() {
    int size = (int)strlen(args.base_host), dot = 0;
    // one more byte for the dot
    if (*(args.base_host) != '.') {
        if (!(*(args.base_host) >= 97 && *(args.base_host) <= 122)) {
            return handle_error(E_HOST_INV_CHAR);
        }
        size += 1;
        dot = 1;
    } else {
        if (!(*(args.base_host + 1) >= 97 && *(args.base_host + 1) <= 122)) {
            return handle_error(E_HOST_INV_CHAR);
        }
    }
    // +1 for null byte at the end
    args.checked_base_host = malloc(sizeof(char) * (size + 1));
    // unsuccessful allocation
    if (!args.checked_base_host) {
        return E_INT;
    }
    *(args.checked_base_host) = '.';
    strcpy(args.checked_base_host + dot, args.base_host);

    // +1 for zero length octet at the end
    // +2 for at least on data byte(label length + one byte of data)
    // >=255 to leave at least one char for the actual data
    if (strlen(args.checked_base_host) + 1 + 2 >= 255) {
        return E_HOST_LEN;
    }
    // check lengths, max label size is 63
    unsigned long count = 0;
    // check label length
    // +1 to check until the `\0` at the end
    unsigned char c;
    for (int i = 0; i < strlen(args.checked_base_host) + 1; i++) {
        c = *(args.checked_base_host + i);
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

int check_dst_filepath() {
    int dot = 0;
    if (args.dst_filepath[strlen(args.dst_filepath) - 1] != '/') {
        dot = 1;
    }
    // +1 for null byte
    char *ptr = malloc(sizeof(char) * (strlen(args.dst_filepath) + dot + 1));
    if (!ptr) {
        return E_INT;
    }

    strcpy(ptr, args.dst_filepath);
    if (dot) {
        ptr[strlen(ptr)] = '/';
    }
    args.dst_filepath = ptr;

    // need this check for stat
    if (access(args.dst_filepath, W_OK)) return E_INT;

    // check if it is a folder
    struct stat stat_res;
    if (stat(args.dst_filepath, &stat_res) != 0)
        return 0;
    if (!S_ISDIR(stat_res.st_mode)) {
        return handle_error(E_NOT_DIR);
    }
    return EXIT_OK;
}

int parse_args(int argc, char *argv[]) {
    if (argc < 3) {
        handle_error(E_NUM_ARGS);
        print_help();
        return E_NUM_ARGS;
    }

    memset(&args, 0, sizeof(struct InputArgs));
    int positional_arg_counter = 0;

    for (size_t i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            if (i != 1) return handle_error(E_INV_ARGS);
            print_help();
            return EXIT_HELP;
        }
        if (!positional_arg_counter) {
            args.base_host = argv[i];
            positional_arg_counter++;
            continue;
        } else if (positional_arg_counter == 1) {
            args.dst_filepath = argv[i];
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

    int res;
    if ((res = check_base_host())) {
        return res;
    }
    if ((res = check_dst_filepath())) {
        return res;
    }
    return EXIT_OK;
}

int send_ack_response(unsigned char *buffer, ssize_t rec_len) {
    struct DNSHeader *dns_header = (struct DNSHeader *)buffer;
    dns_header->qr = ANSWER;
    // response `domain not found` signals ack for given chunk
    dns_header->r_code = NXDOMAIN;

    if (send_packet(sock_fd, &sender_addr, buffer, (int)rec_len)) return E_PKT_SEND;
    return EXIT_OK;
}

int convert_from_dns_format(unsigned char *packet_buffer) {
    int pos = (int) sizeof(struct DNSHeader);
    while (*(packet_buffer + pos) != '\0') {
        int c = *(packet_buffer + pos);
        if (c < 0 || c > 63) {
            return E_INT;
        }
        *(packet_buffer + pos) = '.';
        // +length from length octet + 1 byte length octet
        pos += c + 1;
    }
    return EXIT_OK;
}

void get_data_from_packet(unsigned char *packet_buffer, unsigned char *data_buffer, ssize_t rec_len, int *data_pos) {
    int pos = sizeof(struct DNSHeader);
    unsigned char c = *(packet_buffer + pos);
    *(packet_buffer + rec_len - 4 - strlen(args.base_host) - 1) = '\0';
    int count = *data_pos;
    while (c != '\0') {
        if (c != '.') {
            data_buffer[count] = c;
            *data_pos += 1;
            count += 1;
        }
        pos++;
        c = *(packet_buffer + pos);
    }
}

int get_info_from_first_packet(const unsigned char *packet_buffer) {
    unsigned char buffer[DNS_SIZE] = {0};

    int pos = sizeof(struct DNSHeader);
    int c = *(packet_buffer + pos);

    // increment to skip the first length octet
    pos++;
    int lock = pos;
    int count = 0;
    while (pos < lock + strlen((char *)packet_buffer + lock) - strlen(args.checked_base_host)) {
        for (int i = 0; i < c; i++) {
            buffer[count] = *(packet_buffer + pos + i);
            count++;
        }
        pos += c;
        buffer[count] = '.';
        count++;
        c = *(packet_buffer + pos);
        pos++;
    }
    // remove last dot
    buffer[count - 1] = '\0';
    // allocate space for a complete filepath(folder/name_and_ext)
    args.complete_dst_filepath = malloc(sizeof(char) * ((strlen((char *)buffer) + strlen(args.dst_filepath))));

    if (!args.complete_dst_filepath) {
        return E_INT;
    }
    // copy the folder and then the filename
    strcpy(args.complete_dst_filepath, args.dst_filepath);
    strcpy((args.complete_dst_filepath + strlen(args.dst_filepath)), (char *)buffer);
    return EXIT_OK;
}

int init_socket() {
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    memset(&sender_addr, 0, sizeof(sender_addr));

    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    receiver_addr.sin_port = htons(DNS_PORT);

    if (debug) {
        printf("opening UDP socket(...)\n");
    }
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) return E_SOCK_CRT;
    if (debug) {
        printf("binding with the port %d (%d)\n", ntohs(receiver_addr.sin_port), receiver_addr.sin_port);
    }

    if (bind(sock_fd, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr)) == -1) return E_BIND;
    addr_len = sizeof(sender_addr);
    return EXIT_OK;
}

void sigint_handler(int sig) {
    printf("\nCTRL-C pressed(%d)\n", sig);
    free(args.checked_base_host);
    exit(EXIT_OK);
}

void copy_buffers(const unsigned char *src, unsigned char *dst, ssize_t rec_len) {
    memset(dst, 0, DNS_SIZE);
    for (int i = 0; i < rec_len; i++) {
        *(dst + i) = *(src + i);
    }
}

void decode_buffer(unsigned char *src, unsigned char *dst) {
    memset(dst, 0, DNS_SIZE);
    for (int i = 0, j = 0; i < strlen((char *)src); i += 2, j++) {
        char_base16_decode(src[i], src[i + 1], &(dst[j]));
    }
}

int check_base_host_suffix(char *str) {
    if (!str || !args.checked_base_host) {
        return 0;
    }
    return strcmp(str + strlen(str) - strlen(args.checked_base_host), args.checked_base_host);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);
    // buffer for incoming data
    unsigned char packet_buffer[DNS_SIZE];
    // buffer for incoming data after decoding from dns(dot) format
    unsigned char second_packet_buffer[DNS_SIZE];
    // third buffer only for interface function
    unsigned char third_packet_buffer[DNS_SIZE];
    // buffer for received data
    static unsigned char data_buffer[DNS_SIZE];
    // only DNS size because decoded data is smaller
    unsigned char decoded_data_buffer[DNS_SIZE];

    memset(data_buffer, 0, DNS_SIZE);
    int data_buffer_position = 0;

    int res;
    if ((res = parse_args(argc, argv)) > EXIT_OK) {
        if (res == EXIT_HELP) {
            return EXIT_OK;
        }
        return res;
    }
    if (init_socket()) return E_INIT_CONN;

    // loop for multiple files
    while (1) {
        // total decoded content length from all packets
        int content_length = 0;
        // total length of the current packet
        ssize_t rec_len;
        if (get_packet(sock_fd, &sender_addr, packet_buffer, &rec_len, &addr_len)) return E_INT;

        if (send_ack_response(packet_buffer, rec_len)) return E_INT;

        if (interface) {
            dns_receiver__on_transfer_init((struct in_addr *)&receiver_addr.sin_addr);
        }
        // get the filename from the first packet
        if (get_info_from_first_packet(packet_buffer)) {
            return E_INT;
        }
        // open the output file in binary mode
        if (open_file(args.complete_dst_filepath, "wb", &out_ptr)) return E_OPEN_FILE;
        // option to disable timeout(for debugging)
        if (timeout) {
            if (set_timeout(sock_fd, REC_TO_S)) return E_SET_TIMEOUT;
        }
        int receive_packet_fail = 0;
        int chunk_id = 1;
        while (1) {
            // reset buffers
            memset(packet_buffer, 0, DNS_SIZE);
            memset(second_packet_buffer, 0, DNS_SIZE);
            memset(third_packet_buffer, 0, DNS_SIZE);
            memset(data_buffer, 0, DNS_SIZE);
            memset(decoded_data_buffer, 0, DNS_SIZE);

            // receive new packet
            if ((receive_packet_fail = get_packet(sock_fd, &receiver_addr, packet_buffer, &rec_len, &addr_len))) break;
            // copy to second buffer for processing, to preserve the original packet for ack to sender
            copy_buffers(packet_buffer, second_packet_buffer, rec_len);
            // convert from dns(dot) format
            convert_from_dns_format(second_packet_buffer);
            // check if the suffix is the same as the base host(for skipping other packets)
            if (check_base_host_suffix((char *)(second_packet_buffer + sizeof(struct DNSHeader)))) {
                continue;
            }
            // copy content to preserve it for interface function
            copy_buffers(second_packet_buffer, third_packet_buffer, rec_len);
            // gets all data from packet
            get_data_from_packet(second_packet_buffer, data_buffer, rec_len, &data_buffer_position);
            // comparison to find if the received packet was the last one
            if (*(char *)data_buffer ==  'x') {
                if (send_ack_response(packet_buffer, rec_len)) return E_INT;
                // reset data buffer position for next file
                data_buffer_position = 0;
                break;
            }
            // not printing last info packet(last one contains only x.base_host)
            if (interface) {
                dns_receiver__on_query_parsed(args.complete_dst_filepath,
                                              (char*)(third_packet_buffer + sizeof(struct DNSHeader) + 1));
            }
            // decode received base16 encoded data
            decode_buffer(data_buffer, decoded_data_buffer);
            if (interface) {
                // calling interface function
                dns_receiver__on_chunk_received(
                        (struct in_addr *)&receiver_addr.sin_addr,
                        args.complete_dst_filepath,chunk_id,
                        (int)strlen((char *)data_buffer) / 2);
            }
            // increment counter
            chunk_id++;
            // sum up the total length of the decoded data
            content_length += (int)strlen((char *)data_buffer) / 2;
            //write content to file
            fwrite(decoded_data_buffer, 1, strlen((char *)data_buffer) / 2, out_ptr);
            // reset data buffer position for next packet
            data_buffer_position = 0;
            // send ack to sender
            if (send_ack_response(packet_buffer, rec_len)) return E_INT;
        }
        if (receive_packet_fail) {
            printf("Skipping file, timeout reached.\n");
            free(args.dst_filepath);
            free(args.complete_dst_filepath);
            fclose(out_ptr);
            continue;
        }
        // close output file
        fclose(out_ptr);
        if (timeout) {
            if (unset_timeout(sock_fd)) return E_SET_TIMEOUT;
        }
        if (interface) {
            // calling an interface function
            dns_receiver__on_transfer_completed(args.complete_dst_filepath, content_length);
        }
        // free malloced memory for filepath
        free(args.dst_filepath);
        free(args.complete_dst_filepath);
    }
}
