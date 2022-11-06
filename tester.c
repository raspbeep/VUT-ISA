/**
 * dns_tester
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * Usage: echo-udp-client2 <receiver IP address/domain name> <receiver port number> <tester port number>
 *
 * @file dns_tester.c
 *
 * @brief Client side of DNS tunneling application
 */

#pragma once

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#include<netdb.h>
#include <sys/time.h>

#include "tester.h"

#define BUFFER 1024
#define RECEIVER_IP "127.0.0.1"
#define RECEIVER_PORT 53
#define TESTER_PORT 1645
#define BUFFER 1024

// communication tester <-> receiver
struct sockaddr_in receiver_addr;
int sock_fd_to_receiver;
unsigned long total_len = 0;
ssize_t sent_len = 0;

// communication sender <-> tester
int sock_fd_to_sender;
struct sockaddr_in tester_addr, sender_addr;
int r;
ssize_t received_len = 0;
char buffer[BUFFER];

// common
socklen_t addr_len = sizeof(struct sockaddr_in);


// UDP server for sending messages from sender to receiver
int init_connection_to_receiver() {
    memset(&receiver_addr, 0, sizeof(receiver_addr));
    receiver_addr.sin_family = AF_INET;
    receiver_addr.sin_addr.s_addr = inet_addr(RECEIVER_IP);
    receiver_addr.sin_port = htons(RECEIVER_PORT);

    // create datagram socket
    if ((sock_fd_to_receiver = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        return -1;
    }
    printf("* Socket for communication with receiver created *\n");

    if (connect(sock_fd_to_receiver, (struct sockaddr *)&receiver_addr, addr_len)  == -1) {
        err(1, "connect() failed");
    }
    return 0;
}

// UDP server for listening for messages from sender
int init_connection_to_sender() {
        memset(&receiver_addr, 0, sizeof(tester_addr));
        memset(&sender_addr, 0, sizeof(sender_addr));

        tester_addr.sin_family = AF_INET;
        tester_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        tester_addr.sin_port = htons(TESTER_PORT);

        printf("opening UDP socket for communication sender <-> tester\n");
        if ((sock_fd_to_sender = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            return -1;
        }
        printf("binding with the port %d (%d)\n", ntohs(tester_addr.sin_port), tester_addr.sin_port);
        if (bind(sock_fd_to_sender, (struct sockaddr *)&tester_addr, sizeof(tester_addr)) == -1) {
            return -1;
        }
        return 0;
}

int drop_generator() {
    static int streak = 0;
    if (streak == 1) {
        streak = 0;
        return 0;
    }
    if (rand() % 2 == 1) {
        streak++;
        return 1;
    }
    return 0;
}


int main(int argc, char *argv[]) {
    // create seed for random packet drop generator
    srand(time(NULL));

    memset(buffer, 0, BUFFER);

    if (init_connection_to_receiver() == -1) {
        printf("error while creating socket for communication tester <-> receiver\n");
        return -1;
    }
    if (init_connection_to_sender() == -1) {
        printf("error while creating socket for communication sender <-> tester\n");
        return -1;
    }

    // receive message from sender
    while ((received_len = recvfrom(sock_fd_to_sender, buffer, BUFFER, 0, (struct sockaddr *)&sender_addr, &addr_len)) >= 0) {
        printf("data received from %s, port %d\n", inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port));

        if (!drop_generator()) {
            // send message to receiver
            sent_len = send(sock_fd_to_receiver, buffer, received_len, 0);
            if (sent_len == -1) {
                err(1, "send() failed");
            } else if (sent_len != received_len) {
                err(1, "send(): buffer written partially");
            }

            // receive ACK message from receiver
            if ((received_len = recvfrom(sock_fd_to_receiver, buffer, BUFFER, 0, (struct sockaddr *) &receiver_addr,
                                         &addr_len)) >= 0) {
                // send message to receiver
                sent_len = sendto(sock_fd_to_sender, buffer, received_len, 0, (struct sockaddr *) &sender_addr,
                                  addr_len);
                if (sent_len == -1) {
                    err(1, "send() failed");
                } else if (sent_len != received_len) {
                    err(1, "send(): buffer written partially");
                }
            }
            printf("Successfully sent packet to receiver and confirmed to sender\n");
        } else {
            printf("##### Dropped packet\n");
        }

    }
}