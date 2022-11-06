/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_sender.c
 *
 * @brief
 */

#include "dns_sender.h"

#define RECEIVER_PORT DNS_PORT
#define SND_TO_S 3

struct InputArgs {
    // base domain for all communication
    char *base_host;
    // in a correct format e.g. `.example.com.`
    char *checked_base_host;
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
// output file pointer
FILE *fptr = 0;
// enable timeouts for sending and receiving packets
int timeout = 1;
// enable calling interface functions
int interface = 1;

void print_help() {
    printf( "Usage: ./dns_sender [-u UPSTREAM_DNS_IP] BASE_HOST DST_FILEPATH [SRC_FILEPATH]\n"
            "   UPSTREAM_DNS_IP -   Optional IP to DNS server, which requests are sent to(e.g. 127.0.0.1)\n"
            "   BASE_HOST       -   Required queried host to concatenate with sent data(e.g. example.com)\n"
            "   DST_FILEPATH    -   Required destination file name of transferred data(file.txt)\n"
            "   SRC_FILEPATH    -   Optional path to source file read in binary mode\n\n"
    );
}

int check_base_host() {
    int size = (int)strlen(args.base_host), dot = 0;
    // one more byte for the dot
    if (*(args.base_host) != '.') {
        size += 1;
        dot = 1;
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
    for (int i = 0; i < strlen(args.checked_base_host)+1; i++) {
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

int find_ip_version(const char *src) {
    char buf[64];
    if (inet_pton(AF_INET, src, buf)) {
        return 4;
    } else if (inet_pton(AF_INET6, src, buf)) {
        return 6;
    }
    return handle_error(E_IP_VER);
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
                    return handle_error(E_INT);
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
        return handle_error(E_NM_SRV);
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
    int res;
    if ((res = check_base_host())) {
        return res;
    }
    // upstream DNS server was not given, try to find one in /etc/resolv.conf
    if (!u_flag) {
        if (scan_resolv_conf()) return handle_error(E_NM_SRV);
    }
    return EXIT_OK;
}

int read_char_from_src(int *c) {
    if (args.src_filepath) {
        // if the fptr is not opened yet
        if (!fptr) {
            if (open_file(args.src_filepath, "rb", &fptr)) {
                return handle_error(E_OPEN_FILE);
            }
        }
        // read binary file
        *c = fgetc(fptr);
        if (*c == EOF) {
            return 1;
        }
        return EXIT_OK;
    }

    *c = fgetc(stdin);
    if (*c == EOF) {
        return 1;
    }
    // either valid char or EOF was read
    return EXIT_OK;
}

int get_next_encoded_char(char *ret) {
    int c;
    static char store_encoded = -1;

    // return one already stored
    if (store_encoded != -1) {
        *ret = store_encoded;
        store_encoded = -1;
        return EXIT_OK;
    }

    // read new char
    if (read_char_from_src(&c) == 1) {
        return 1;
    }

    if (c == EOF) {
        return 1;
    }
    char_base16_encode((char)c, ret, &store_encoded);
    return EXIT_OK;
}

void convert_dns_format(unsigned char *packet_buffer, int packet_buffer_pos) {
    for (int i = (int) sizeof(struct DNSHeader); i < packet_buffer_pos; i++) {
        if (*(packet_buffer + i) == '.') {
            int count = 0;
            int pos = i + 1;
            while (*(packet_buffer + pos) != '.' && *(packet_buffer + pos) != '\0') {
                count++;
                pos++;
            }
            *(packet_buffer + i) = count;
        }
    }
}

int init_socket() {
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = inet_addr(args.upstream_dns_ip);
    receiver_addr.sin_port = htons(RECEIVER_PORT);

    // create datagram socket
    if ((sock_fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return handle_error(E_SOCK_CRT);
    }

    return EXIT_OK;
}

int send_first_info_packet() {
    unsigned char buffer[DNS_SIZE] = {0};
    int id = 0, pos = 0;
    construct_dns_header((buffer), id);
    pos += sizeof(struct DNSHeader);

    // for first length octet
    *(buffer + pos) = '.';
    pos += 1;

    strcpy((char *)(buffer + pos), args.dst_filepath);
    pos += (int)strlen(args.dst_filepath);

    strcpy((char *)(buffer + pos), args.checked_base_host);
    pos += (int)strlen(args.checked_base_host);
    // zero length octet
    pos += 1;
    // convert from dot format to length octet format
    convert_dns_format(buffer, pos);

    construct_dns_question(buffer + pos);
    pos += sizeof(struct Question);

    ssize_t rec_len;
    int res;

    if ((res = send_and_wait(sock_fd, &receiver_addr, buffer, pos, &rec_len,
                  &addr_len, id)) != 0) {
        return res;
    }
    return EXIT_OK;
}

int send_last_info_packet(int id) {
    unsigned char buffer[DNS_SIZE] = {0};
    int pos = 0;
    construct_dns_header((buffer), id);
    pos += sizeof(struct DNSHeader);

    // for first length octet
    *(buffer + pos) = '.';
    pos += 1;

    *(buffer + pos) = 'x';
    pos += 1;

    strcpy((char *)(buffer + pos), args.checked_base_host);
    pos += (int)strlen(args.checked_base_host);
    // zero length octet
    pos += 1;
    // convert from dot format to length octet format
    convert_dns_format(buffer, pos);
    // add DNS question section(0 1 0 1)
    construct_dns_question(buffer + pos);
    pos += sizeof(struct Question);

    ssize_t rec_len;
    int res;
    if ((res = send_and_wait(sock_fd, &receiver_addr, buffer, pos, &rec_len,
                             &addr_len, id)) != 0) {
        return res;
    }
    return EXIT_OK;
}

int send_packets() {
    int packet_buffer_pos = 0;
    unsigned char packet_buffer[DNS_SIZE];
    ssize_t rec_len;

    if (init_socket()) return E_INIT_CONN;

    if (timeout) {
        if (set_timeout(sock_fd, SND_TO_S)) return E_INT;
    }
    if (interface) {
        dns_sender__on_transfer_init((struct in_addr *) &receiver_addr.sin_addr);
    }
    // send packet with destination file name
    send_first_info_packet();
    // char currently inserted into buffer
    char c;
    // stops on break from inside
    int chunk_n = 1, chunk_id;
    // -1 zero length octet at the end
    int packet_data_capacity = QNAME_SIZE - strlen(args.checked_base_host) - 1;
    int current_packet_data_capacity;
    // sends all packets
    while (1) {
        int res;
        // set maximum length for each packet
        current_packet_data_capacity = packet_data_capacity;
        // position in the buffer
        packet_buffer_pos = 0;
        // empty the buffer
        memset(packet_buffer, 0, DNS_SIZE);
        // get new chunk id, take care of id overflow
        chunk_id = (int)(chunk_n) % (1 << 16);
        // create header and shift `pos`
        construct_dns_header(packet_buffer, chunk_id);
        packet_buffer_pos += sizeof(struct DNSHeader);
        // label capacity left in current label section
        int label_capacity = LABEL_SIZE;
        // count of chars in one label section
        int label_count = 0;
        // locks at the last length octet
        int lock = packet_buffer_pos;
        int byte_count = 0;
        // for checking oddness of the number of chars(due to decoding)
        int char_count = 0;
        // an indication last encoded char was read
        int last_char = 1;
        // fill one packet to its capacity
        while (current_packet_data_capacity) {
            // if there is space in current label
            if (label_capacity && !(current_packet_data_capacity == 1 && char_count % 2 == 0)) {
                // if EOF is found
                if ((last_char = get_next_encoded_char(&c)) != 0) {
                    *(packet_buffer + lock) = '.';
                    packet_buffer_pos++;
                    break;
                }
                char_count++;
                *(packet_buffer + packet_buffer_pos + 1) = c;
                label_capacity--;
                packet_buffer_pos++;
                label_count++;
                current_packet_data_capacity--;
                byte_count++;
            } else {
                *(packet_buffer + lock) = '.';
                lock += label_count + 1;
                packet_buffer_pos++;
                label_count = 0;
                current_packet_data_capacity--;
                label_capacity = LABEL_SIZE;
            }
        }
        // copy base host into buffer
        strcpy((char *)(packet_buffer + packet_buffer_pos), args.checked_base_host);
        // add its length to the buffer position
        packet_buffer_pos += (int)strlen(args.checked_base_host);

        if (interface) {
            dns_sender__on_chunk_encoded(args.dst_filepath,
                                         chunk_n,
                                         // +1 to omit dot at the beginning
                                         (char *)packet_buffer + sizeof(struct DNSHeader) + 1);
        }
        // convert dns(dot) format to dns(length) format
        convert_dns_format(packet_buffer, packet_buffer_pos);
        // add null byte and move next
        packet_buffer_pos += 1;
        // add question to the end of the buffer (0 1 0 1)
        construct_dns_question(packet_buffer + packet_buffer_pos);
        packet_buffer_pos += sizeof(struct Question);
        // calling interface function
        if (interface) {
            // char count / 2 because the encoded length is twice the original
            dns_sender__on_chunk_sent((struct in_addr *) &receiver_addr.sin_addr,
                                      args.dst_filepath, chunk_n, char_count / 2);
        }

        if ((res = send_and_wait(sock_fd, &receiver_addr, packet_buffer,
                                 packet_buffer_pos, &rec_len,
                                 &addr_len, chunk_id))) {
            return res;
        }
        chunk_n++;
        total_len += char_count / 2;
        // break after the last char, all data were sent
        if (last_char) {
            break;
        }
    }
    send_last_info_packet((int)(chunk_n) % (1 << 16));
    if (interface) {
        dns_sender__on_transfer_completed(args.dst_filepath, (int)total_len);
    }
    return EXIT_OK;
}

int main(int argc, char *argv[]) {
    int result;
    // parse and store input arguments
    result = parse_args(argc, argv);
    // return 0 if `--help`
    if (result == EXIT_HELP) return EXIT_OK;
    if (result) return result;
    // send data
    send_packets();
    // close
    close(sock_fd);
    return EXIT_OK;
}
