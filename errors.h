/**
 * dns_sender
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file errno.h
 *
 * @brief Error number header file
 */

#pragma once

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
#define E_WR_PERM 8
// error occurred opening source or destination file
#define E_OPEN_FILE 9
// error occurred reading input file
#define E_RD_FILE 10
// base host does not meet length requirements(name is longer than 63 chars
// or total length exceeds )
#define E_HOST_LEN 11
// error during sending packet
#define E_PKT_SEND 12
// error during receiving packet
#define E_PKT_REC 13
// error initializing connection
#define E_INIT_CONN 14
// error creating a socket endpoint for communication
#define E_SOCK_CRT 15
// error binding to socket
#define E_BIND 16
// error timeout reached
#define E_TIMEOUT 17
// error scanning /etc/resolv.conf
#define E_NM_SRV 18
