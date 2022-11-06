cmake_minimum_required(VERSION 3.23)
project(dns_sender_receiver C)

set(CMAKE_C_STANDARD 99)

add_executable( dns_sender sender/dns_sender.c sender/dns_sender.h
        common/common.c sender/dns_sender_events.h sender/dns_sender_events.c)

add_executable( dns_receiver receiver/dns_receiver.h receiver/dns_receiver.c
        common/common.c receiver/dns_receiver_events.h receiver/dns_receiver_events.c)

add_executable(dns_tester tester/dns_tester.c tester/dns_tester.h)