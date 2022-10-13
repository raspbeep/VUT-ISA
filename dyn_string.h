/**
 * dns_tunneling
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dyn_string.h
 *
 * @brief Dynamic string header file
 */

#pragma once

#include <stddef.h>
#include "errors.h"

#define STRING_ALLOC_LENGTH 16

typedef struct {
    char *ptr;
    unsigned long alloc_length;
    unsigned long length;
} string_t;

int str_create_empty(string_t *str);

int str_append_char(string_t *str, char ch);

int str_append_string(string_t *str, char *s);

void str_free(string_t *str);

int str_append_strings(string_t *dst, string_t *src);

int str_base16_decode(string_t *src, string_t *dst);

int str_base16_encode(string_t *src, string_t *dst);

int str_base_host_label_format(string_t *src, string_t *dst);

void str_copy_to_buffer(string_t *src, unsigned char *buffer);
