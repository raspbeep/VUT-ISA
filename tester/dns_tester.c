/**
 * dns_tester
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * Usage: echo-udp-client2 <receiver IP address/domain name> <receiver port number> <tester port number>
 *
 * @file dns_tester.c
 *
 * @brief Testing of DNS tunneling application
 */

#include "dns_tester.h"

#define BUFFER 1024
#define RECEIVER_IP "0.0.0.0"
#define RECEIVER_PORT 53
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

int drop_generator_bin() {
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

int change_generator() {
    return rand() % 2;
}

void change_packet_id() {
    struct DNSHeader *dns_header = (struct DNSHeader *)buffer;
    int orig_id = ntohs(dns_header->id);
    dns_header->id = htons(orig_id - 1);
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

        // don't do anything with the packet
        if (!drop_generator_bin()) {
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
            // change something or drop

            int change = change_generator();
            // drop it
            if (change == 0) {
                continue;
            } else if (change == 1) {
                printf("Changing packet id\n");
                change_packet_id();
            }

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
        }
    }
}