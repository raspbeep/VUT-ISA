/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_sender.h
 *
 * @brief Header for the client side of DNS tunneling application
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

#include "../common/common.h"
#include "dns_sender_events.h"
#include <string.h>

/*
 * Function: print_help.
 * --------------------
 *   Prints help message
 */
void print_help();

/*
 * Function: check_base_host
 * ----------------------------
 *   Checks whether the base host is a valid FQDN(and < 252 chars, no spaces, no special chars).
 *
 *   returns: EXIT_OK(0) on success, E_HOST_LEN or E_HOST_INV_CHAR on error
 */
int check_base_host();

/*
 * Function: find_ip_version
 * ----------------------------
 *   Finds IP version of the given IP address.
 *
 *   src: pointer to IP char array
 *
 *   returns: EXIT_OK(0) on success, E_POS_ARG on error
 */
int find_ip_version(const char *src);

/*
 * Function: scan_resolv_conf
 * ----------------------------
 *   Attempts to get the first nameserver from /etc/resolv.conf.
 *
 *   returns: EXIT_OK(0) on success, E_INT, E_NM_SRV on error
 */
int scan_resolv_conf();

/*
 * Function: parse_args
 * ----------------------------
 *   Assigns global variables(args.dst_filepath) from command line arguments.
 *
 *   argc: number of arguments
 *   argv: array of program arguments
 *
 *   returns: EXIT_OK(0) on success, E_POS_ARG on error
 */
int parse_args(int argc, char *argv[]);

/*
 * Function: read_char_from_src
 * ----------------------------
 *   Reads next character from either STDIN or source file.
 *
 *   c: pointer to char variable
 *
 *   returns: EXIT_OK(0) on success, E_OPEN_FILE or E_RD_FILE on error
 */
int read_char_from_src(int *c);

/*
 * Function: get_next_encoded_char
 * ----------------------------
 *   Calls read_char_from_src(), encodes it and returns it. Function has static variable for storing
 *   the second part of the encoded character(base16 splits char into two).
 *
 *   ret: an encoded character
 *
 *   returns: EXIT_OK(0) on success, 1 on EOF
 */
int get_next_encoded_char(char *ret);

/*
 * Function: convert_dns_format
 * ----------------------------
 *   Converts dot format into length octet DNS format.
 *
 *   packet_buffer: buffer to convert
 *   packet_buffer_pos: position where data begins in packet_buffer
 */
void convert_dns_format(unsigned char *packet_buffer, int packet_buffer_pos);

/*
 * Function: init_socket
 * ----------------------------
 *   Initializes socket for sending DNS queries and binds to it.
 *
 *   returns: EXIT_OK(0) on success, E_SOCK_CRT on error
 */
int init_socket();

/*
 * Function: parse_args
 * ----------------------------
 *   Sends first packet with dst_filename.
 *
 *   returns: EXIT_OK(0) on success, result of sending on error
 */
int send_first_info_packet();

/*
 * Function: send_last_info_packet
 * ----------------------------
 *   Sends last packet with content of 'x.base_host'.
 *
 *   id: id of the last packet
 *
 *   returns: EXIT_OK(0) on success, result of sending on error
 */
int send_last_info_packet(int id);

/*
 * Function: send_packets
 * ----------------------------
 *   The main function of sender. Organizes sending of all packets and receiving ack-s from receiver.
 *
 *   argc: number of arguments
 *   argv: array of program arguments
 *
 *   returns: EXIT_OK(0) on success, E_POS_ARG on error
 */
int send_packets();
