cmake_minimum_required(VERSION 3.23)
project(dns_tunneling_server_client C)

set(CMAKE_C_STANDARD 99)

add_executable(dns_tunneling_server_client dns_sender.c dns_sender.h dns_receiver.c dns_receiver.h dyn_string.h dyn_string.c)
