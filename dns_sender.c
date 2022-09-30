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
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>

// should be used eventually
//#include <sys/types.h>
//#include <netinet/in.h>
//#include <arpa/nameser.h>
//#include <resolv.h>

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
    printf( "dns_sender \n"
            "Usage: ./dns_sender \n"
            "\n"
            "\n"
            "\n\n"
    );
}

int parse_args(int argc, char *argv[], struct InputArgs* args) {
    if (argc < 2 || argc > 7) {
        return handle_error(E_NUM_ARGS);
    }

    // clear the struct values
    memset(args, 0, sizeof(struct InputArgs));

    int positional_arg_counter = 0;
    bool b_flag = false;
    bool u_flag = false;

    for (size_t i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "--help")) {
            if (argc != 2) return handle_error(E_INV_ARGS);
            print_help();
            return EXIT_H;
        }

        if (!strcmp(argv[i], "-b")) {
            if (b_flag) return handle_error(E_RE_B_ARGS);
            args->base_host = argv[++i];
            b_flag = true;
            continue;
        }

        if (!strcmp(argv[i], "-u")) {
            if(u_flag) return handle_error(E_RE_U_ARGS);
            args->upstream_dns_ip = argv[++i];
            u_flag = true;
            continue;
        }

        if (!positional_arg_counter) {
            args->dst_filepath = argv[i];
            positional_arg_counter++;
            continue;
        } else if (positional_arg_counter == 1){
            args->src_filepath = argv[i];
            continue;
        } else {
            return handle_error(E_POS_ARG);
        }
    }

    // no positional arguments were found
    if (!positional_arg_counter) {
        return handle_error(E_POS_ARG);
    }
    return EXIT_OK;
}


int open_file(const char *path, int oflag, int *fd) {
    *fd = open(path, oflag);
    if (fd < 0) return E_OPEN_FILE;
    return 0;
}

int read_src(char *src_filepath, string_t *buffer) {
    // initialize file descriptor to 0(stdin)
    int fd = 0;

    if (src_filepath) {
        // check reading permission
        if (access(src_filepath, R_OK)) {
            return E_RD_PERM;
        }
        // get file descriptor of open file(only for reading)
        if (open_file(src_filepath, O_RDONLY, &fd)) {
            return E_OPEN_FILE;
        }
    }

    // initialize empty string
    if (str_create_empty(buffer)) {
        return E_INT;
    }

    // store input in buffer
    char c;
    while(1) {
        switch (read(fd, &c, 1)) {
            // found EOF
            case 0:
                if (src_filepath) {
                    if (close(fd)) {
                        return E_INT;
                    }
                }
                return EXIT_OK;
            // correctly read one byte
            case 1:
                if (str_append_char(buffer, c)) {
                    return E_INT;
                }
                break;
            // occurred an error reading input file
            default:
                if (src_filepath) {
                    if (close(fd)) {
                        return E_INT;
                    }
                }
                return E_RD_FILE;
        }
    }


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

    printf("base host: %s\n", args.base_host);
    printf("upstream dns ip: %s\n", args.upstream_dns_ip);
    printf("dst filepath: %s\n", args.dst_filepath);
    printf("src filepath: %s\n", args.src_filepath);

    return 0;
}
