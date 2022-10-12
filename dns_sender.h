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
int check_base_host(string_t *base_host);

int format_base_host_string();

int find_ip_version(const char *src);

int scan_resolv_conf();

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
int read_src(string_t *buffer);

/**
 * Splits encoded data into chunks and converts into DNS format(e.g. 3aaa2bb1c0)
 * to use the maximum available space in queried name. The length inserted
 * into each packet depends on the length of given base_host(the longer the base
 * host name, the smaller the resulting capacity). Therefore, the maximum set
 * length for base host name is 252B(maximum allowed is 255 - 1 zero length
 * octet at the end - 1B data length octet and - 1B data).
 *
 *
 * @param base_host base host to appended in DNS format to each QNAME
 * @param data all data to send
 * @param chunks pointer to array of data chunks to send
 * @param n_chunks number of chunks(packets) to send
 *
 * @returns
 */
int split_into_chunks(string_t *data, string_t **chunks, unsigned long *n_chunks);

int init_connection();

int send_first_info_packet(unsigned long n_chunks, unsigned char *buffer, int *pos, ssize_t *rec_len);

int dns_packet(string_t **chunks, unsigned long n_chunks);

void free_chunks(string_t **chunks, unsigned long n_chunks);
