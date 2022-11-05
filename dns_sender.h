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
#include "dns_sender_events.h"
#include <string.h>

void print_help();


int check_base_host();


int find_ip_version(const char *src);


int scan_resolv_conf();


int parse_args(int argc, char *argv[]);


int read_char_from_src(int *c);


int get_next_encoded_char(char *ret);


void convert_dns_format(unsigned char *packet_buffer, int packet_buffer_pos);


int init_socket();


int send_first_info_packet();


int send_last_info_packet();


int send_packets();
