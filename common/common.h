/**
 *  common
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file common.h
 *
 * @brief Header for common functions for dns_sender, dns_receiver and dns_tester
 */

#pragma once

#include <arpa/inet.h>
#include <stdio.h>
#include <netinet/in.h>

// default DNS port
#define DNS_PORT 53
// default DNS tester port
#define TESTER_PORT 1645
// max size of DNS packet sent over UDP
#define DNS_SIZE 512
// max size for a FQDN(stored in DNS packet as QNAME)
#define QNAME_SIZE 255
// two bits out of eight are reserved for reference distinction
#define LABEL_SIZE 63
// retry count for sending and receiving packets
#define RETRY_N 3
// DNS kind of query codes
#define QUERY 0
#define ANSWER 1
// DNS code for function not implemented
#define DNS_BAD_FORMAT_ACK 4

// ERROR NUMBERS DEFINITIONS
#define EXIT_OK 0
// internal error
#define E_INT 1
// exit printing an error message
#define EXIT_HELP 2
// invalid number of given arguments
#define E_NUM_ARGS 3
// invalid arguments
#define E_INV_ARGS 4
// redefinition of -u flag
#define E_RE_U_ARGS 5
// incorrect positional arguments
#define E_POS_ARG 6
// insufficient permission for writing to output file
#define E_RD_PERM 7
// insufficient permission for reading input file
#define E_NOT_DIR 8
// error occurred opening source or destination file
#define E_OPEN_FILE 9
// error occurred reading input file
#define E_RD_FILE 10
// base host does not meet length requirements(name is longer than 63 chars
// or total length exceeds )
#define E_HOST_LEN 11
// invalid char in base host, only alphanumeric are allowed
#define E_HOST_INV_CHAR 12
// error during sending packet
#define E_PKT_SEND 13
// error during receiving packet
#define E_PKT_REC 14
// error initializing connection
#define E_INIT_CONN 15
// error creating a socket endpoint for communication
#define E_SOCK_CRT 16
// error binding to socket
#define E_BIND 17
// error timeout reached
#define E_TIMEOUT 18
// error setting timeout(setsockopt)
#define E_SET_TIMEOUT 19
// error scanning /etc/resolv.conf
#define E_NM_SRV 20
// error determining IP address
#define E_IP_VER 21
// destination filepath parameter is too long
#define E_DST_PATH_LEN 22

// DNS header struct
struct DNSHeader {
    unsigned short id: 16;      // identification

    unsigned char rd: 1;        // recursion desired
    unsigned char tc: 1;        // truncated
    unsigned char aa: 1;        // authoritative answer
    unsigned char opcode: 4;    // kind of query
    unsigned char qr: 1;        // query/response

    unsigned char r_code: 4;    // response code
    unsigned char cd: 1;        // authenticated data
    unsigned char ad: 1;        // checking disabled
    unsigned char z: 1;         // reserved

    unsigned char ra: 1;        // recursion available

    unsigned short q_count;     // 16b question count
    unsigned short ans_count;   // 16b answer count
    unsigned short ns_count;    // 16b nameserver RRS count
    unsigned short ar_count;    // 16b additional RRs count
};

// DNS question struct(at the end of DNS packet query)
struct Question {
    unsigned short q_type;      // 16b TYPE code field
    unsigned short q_class;     // 16b class of the query
};

/*
 * Function: construct_dns_question
 * ----------------------------
 *   Constructs DNS question part of DNS packet. Buffer has to be already pointing
 *   at the end of DNS data.
 *
 *   buffer: packet buffer
 */
void construct_dns_question(unsigned char *buffer);

/*
 * Function: construct_dns_header
 * ----------------------------
 *   Creates the DNS header with a specified id at the beginning of the DNS packet.
 *
 *   buffer: packet buffer
 *   id: identification number of the DNS packet
 */
void construct_dns_header(unsigned char *buffer, unsigned int id);

/*
 * Function: open_file
 * ----------------------------
 *   Opens a file in a specified read mode and assigns it to a pointer.
 *
 *   path: path to the file
 *   read_mode: read mode in which to open the file
 *   fptr: double pointer to the file(for assigning it inside the function)
 *
 *   returns: EXIT_OK(0) on success, E_RD_PERM or E_OPEN_FILE on error
 */
int open_file(const char *path, const char *read_mode, FILE **fptr);

/*
 * Function: send_packet
 * ----------------------------
 *   Sends a packet.
 *
 *   sock: socket file descriptor
 *   addr: address to send the packet to
 *   buffer: data to send
 *   pos: position(length of data to send) in buffer
 *
 *   returns: EXIT_OK(0) on success, E_TIMEOUT or E_PKT_SEND on error
 */
int send_packet(int sock, struct sockaddr_in *addr, unsigned char *buffer, int pos);

/*
 * Function: get_packet
 * ----------------------------
 *   Receives a packet.
 *
 *   sock: socket file descriptor
 *   addr: address to send the packet to
 *   buffer: data to send
 *   rec_len: received length
 *   addr_len: length of address
 *
 *   returns: EXIT_OK(0) on success, E_TIMEOUT or E_PKT_REC on error
 */
int get_packet(int sock, struct sockaddr_in *addr, unsigned char *buffer, ssize_t *rec_len, socklen_t *addr_len);

/*
 * Function: get_packet_rc
 * ----------------------------
 *   Gets result code from packet header.
 *
 *   buffer: buffer with DNS packet
 *
 *   returns: result code in packet
 */
unsigned char get_packet_rc(unsigned char *buffer);

/*
 * Function: get_packet_a_count
 * ----------------------------
 *   Gets sum all all answer fields from packet header.
 *
 *   buffer: buffer with DNS packet
 *
 *   returns: answers in packet
 */
unsigned char get_packet_a_count(unsigned char *buffer);

/*
 * Function: get_packet_id
 * ----------------------------
 *   Gets identification number from DNS packet.
 *
 *   buffer: buffer with DNS packet
 *
 *   returns: id of packet
 */
unsigned int get_packet_id(unsigned char *buffer);

/*
 * Function: send_and_wait
 * ----------------------------
 *   Send a packet to the server and wait for a response.
 *
 *   sock_fd: socket file descriptor
 *   addr: address to send the packet to
 *   buffer: data to send
 *   pos: position(length of data to send) in buffer
 *   rec_len: received length
 *   addr_len: length of address
 *   id: identification of packet
 *
 *   returns: EXIT_OK(0) on success, E_PKT_REC or E_PKT_SEND on error
 */
int send_and_wait(int sock_fd, struct sockaddr_in *addr, unsigned char *buffer,
                  int pos, ssize_t *rec_len, socklen_t *addr_len, int id);

/*
 * Function: set_timeout
 * ----------------------------
 *   Sets timeout for socket
 *
 *   sock_fd: socket file descriptor
 *
 *   returns: EXIT_OK(0) on success, E_SET_TIMEOUT on error
 */
int set_timeout(int sock_fd, int to_s);

/*
 * Function: unset_timeout
 * ----------------------------
 *   Unsets timeout for socket
 *
 *   sock_fd: socket file descriptor
 *
 *   returns: EXIT_OK(0) on success, E_SET_TIMEOUT on error
 */
int unset_timeout(int sock_fd);

/*
 * Function: char_base16_decode
 * ----------------------------
 *   Decodes a two base16 encoded characters to binary.
 *
 *   a: first input base16 encoded character
 *   b: second input base16 encoded character
 *   c: output binary character
 */
void char_base16_decode(unsigned char a, unsigned char b, unsigned char *c);

/*
 * Function: char_base16_encode
 * ----------------------------
 *   Encodes a single character(c) to two base16(a and b).
 *
 *   c: input character(binary)
 *   a: first base16 output character
 *   b: second base16 output character
 */
void char_base16_encode(char c, char *a, char *b);

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
 * Function: handle_error
 * ----------------------------
 *   Prints error message and returns argument err_n.
 *
 *   err_n: number of arguments
 *
 *   returns: err_n
 */
int handle_error(int err_n);
