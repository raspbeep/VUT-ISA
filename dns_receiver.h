/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_sender.h
 *
 * @brief
 */

#pragma once

#include <string.h>

#include "dyn_string.h"

void print_help();

/**
 *
 *
 *
 * @param
 *
 * @returns
 */
int parse_args(int argc, char *argv[]);

/**
 *
 *
 *
 * @param
 *
 * @returns
 */
int check_dst_filepath(char *dst_filepath, string_t *filepath_string);

/**
 *
 *
 *
 * @param
 *
 * @returns
 */
int get_buffer_data(unsigned char *buffer, string_t *data, char *base_host, string_t *file_path_string);

/**
 *
 *
 *
 * @param
 *
 * @returns
 */
int send_ack_response(unsigned char *buffer, ssize_t rec_len);

/**
 *
 *
 *
 * @param
 *
 * @returns
 */
int get_info_from_first_packet(unsigned char *buffer, long unsigned *chunk_n, char **dst_filepath);

/**
 *
 *
 *
 * @param
 *
 * @returns
 */
int init_connection();

/**
 *
 *
 *
 * @param
 *
 * @returns
 */
void sigint_handler(int sig);
