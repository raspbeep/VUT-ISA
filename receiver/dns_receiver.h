/**
 * dns_receiver
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_receiver.h
 *
 * @brief Header for the server side of DNS tunneling application
 */

#pragma once

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "../common/common.h"
#include "dns_receiver_events.h"

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
 * Function: check_dst_filepath
 * ----------------------------
 *   Checks whether the destination filepath is valid and writeable.
 *
 *   returns: EXIT_OK(0) on success, E_INT or E_NOT_DIR on error
 */
int check_dst_filepath();

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
 * Function: send_ack_response
 * ----------------------------
 *   Sends ack response back to sender, changing response to 'No such name'.
 *
 *   buffer: buffer of received data
 *   rec_len: length of data in buffer
 *
 *   returns: EXIT_OK(0) on success, E_PKT_SEND on error
 */
int send_ack_response(unsigned char *buffer, ssize_t rec_len);

/*
 * Function: convert_from_dns_format
 * ----------------------------
 *   Converts data in packet_buffer from DNS format to dot format.
 *
 *   packet_buffer: packet contents
 *
 *   returns: EXIT_OK(0) on success, E_INT on error
 */
int convert_from_dns_format(unsigned char *packet_buffer);

/*
 * Function: get_data_from_packet
 * ----------------------------
 *   Returns data(stripping Header and Question section) in data_buffer.
 *
 *   packet_buffer: pointer to packet buffer
 *   data_buffer: pointer to (stripped) data buffer
 *   rec_len: length of received data
 *   data_pos: position where data begin in packet buffer
 *
 */
void get_data_from_packet(unsigned char *packet_buffer, unsigned char *data_buffer, ssize_t rec_len, int *data_pos);

/*
 * Function: get_info_from_first_packet
 * ----------------------------
 *   Sets the global variables(dst_filepath, complete_dst_filepath) from the first packet.
 *
 *   packet_buffer: raw received data
 *
 *   returns: EXIT_OK(0) on success, E_INT on error
 */
int get_info_from_first_packet(const unsigned char *packet_buffer);

/*
 * Function: init_socket
 * ----------------------------
 *   Creates a new socket and binds it to the specified port.
 *
 *   returns: EXIT_OK(0) on success, E_SOCK_CRT or E_BIND on error
 */
int init_socket();

/*
 * Function: sigint_handler
 * ----------------------------
 *   Deallocates memory and terminates program.
 *
 *   sig: sig signal
 *
 */
void sigint_handler(int sig);

/*
 * Function: copy_buffers
 * ----------------------------
 *   Copies rec_len number of bytes from src to dst.
 *
 *   src: source buffer
 *   dst: destination buffer
 *
 */
void copy_buffers(const unsigned char *src, unsigned char *dst, ssize_t rec_len);

/*
 * Function: decode_buffer
 * ----------------------------
 *   Returns custom base16 decoded data in dst buffer.
 *
 *   src: encoded data
 *   dst: decoded data
 *
 */
void decode_buffer(unsigned char *src, unsigned char *dst);

/*
 * Function: check_base_host_suffix
 * ----------------------------
 *   Returns whether the buffer ends with set base host.
 *
 *   str: received data buffer in dot format
 *
 *   returns: string comparison result of args.checked_host and str
 */
int check_base_host_suffix(char *str);
