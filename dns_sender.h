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


/**
 *
 *
 *
 * @param
 *
 * @returns
 */
int find_ip_version(const char *src);

/**
 * Attempts to access, read and parse /etc/resolf.conf file. Looks for
 *
 */
int scan_resolv_conf();

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

/**
 * Initializes socket and binds to it using global variables receiver_addr, addr_len and sock_fd.
 *
 */
int init_socket();

/**
 * Sends info about the transmitted file in the form of a DNS packet.
 * Used format is: || HEADER || n_chunks.dst_filepath.base-host-domain.tld || question info ||
 *
 */
int send_first_info_packet(unsigned long n_chunks, unsigned char *buffer, int *pos);
