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


