cmake_minimum_required(VERSION 3.23)
project(dns_sender_receiver C)

set(CMAKE_C_STANDARD 99)


add_executable( dns_sender dns_sender.c dns_sender.h dyn_string.c dyn_string.h
        common.c dns_sender_events.h dns_sender_events.c)

add_executable( dns_receiver dns_receiver.h dns_receiver.c dyn_string.c dyn_string.h
        common.c dns_receiver_events.h dns_receiver_events.c)

add_executable(dns_tester tester.c tester.h)