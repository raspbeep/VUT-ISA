/**
 * dns_tester
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dns_tester.h
 *
 * @brief Header for testing of DNS tunneling application
 */

#pragma once

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../common/common.h"

/*
 * Function: check_base_host
 * ----------------------------
 *   Checks whether the base host is a valid FQDN(and < 252 chars, no spaces, no special chars).
 *
 *   returns: EXIT_OK(0) on success, E_HOST_LEN or E_HOST_INV_CHAR on error
 */
int init_connection_to_receiver();

/*
 * Function: check_base_host
 * ----------------------------
 *   Checks whether the base host is a valid FQDN(and < 252 chars, no spaces, no special chars).
 *
 *   returns: EXIT_OK(0) on success, E_HOST_LEN or E_HOST_INV_CHAR on error
 */
int init_connection_to_sender();

/*
 * Function: drop_generator_bin
 * ----------------------------
 *   Generates a random number mod 2 but ensuring that the streak is smaller than 2.
 *
 *   returns: EXIT_OK(0) on success, E_HOST_LEN or E_HOST_INV_CHAR on error
 */
int drop_generator_bin();

/*
 * Function: change_generator
 * ----------------------------
 *   Generate
 *
 *   returns: random number mod 2
 */
int change_generator();

/*
 * Function: change_packet_id
 * ----------------------------
 *   Changes the packet ID of the DNS packet.
 */
void change_packet_id();
