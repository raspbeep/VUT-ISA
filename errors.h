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

#define EXIT_H 2
// invalid number of given arguments
#define E_NUM_ARGS 3
// invalid arguments
#define E_INV_ARGS 4
// redefinition of -b flag
#define E_RE_B_ARGS 5
// redefinition of -u flag
#define E_RE_U_ARGS 6
// incorrect positional arguments
#define E_POS_ARG 7
// insufficient permission for writing to output file
#define E_RD_PERM 8
// insufficient permission for reading input file
#define E_WR_PERM 9
// error occurred opening source or destination file
#define E_OPEN_FILE 10
// error occurred reading input file
#define E_RD_FILE 11
// base host does not meet length requirements(name is longer than 63 chars
// or total length exceeds )
#define E_HOST_LEN 12

#define E_PKT_SEND 13

#define E_PKT_REC 14

#define E_INIT_CONN 15
// error creating a socket endpoint for communication
#define E_SOCK_CRT 16
// error initiating connection on a socket
#define E_CONNECT 17

#define E_TIMEOUT 18

#define E_SND_TO 19

#define E_REC_TO 20

#define E_NM_SRV 21
