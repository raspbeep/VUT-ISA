/**
 * ipk-sniffer
 *
 * Copyright 2022 xkrato61 Pavel Kratochvil
 *
 * @file dynamic-string.c
 *
 * @brief Dynamic string implementation
 */

#include "dyn_string.h"
#include "errors.h"
#include <stdlib.h>
#include <string.h>

// allocates pre-defined amount for space for empty string
int str_create_empty(string_t *str) {
    // allocate initial space for string
    str->ptr = malloc(STRING_ALLOC_LENGTH);
    if(str->ptr == NULL) {
        return E_INT;
    }
    str->ptr[0] = '\0';
    str->alloc_length = STRING_ALLOC_LENGTH;
    str->length = 0;
    return EXIT_OK;
}

// appends entire string s(ending with \0) to string content
int str_append_string(string_t *str, char *s) {
    for (unsigned long i = 0; i < strlen(s); i++) {
        if (str_append_char(str,s[i])) {
            return E_INT;
        }
    }
    return EXIT_OK;
}

// appends one character to string content
int str_append_char(string_t *str, char ch) {
    // new_char + null byte = 2
    if(str->length + 2 > str->alloc_length) {
        /* allocate buffer twice as large
         * note: str->alloc_length can't be equal to 0 unless STRING_ALLOC_LENGTH is set to 0 or an
         * overflow happened
         */
        str->alloc_length *= 2;
        void *tmp = realloc(str->ptr, str->alloc_length);
        if(tmp == NULL) {
            return E_INT;
        }
        str->ptr = tmp;
    }
    str->ptr[str->length++] = ch;
    str->ptr[str->length] = '\0';
    return EXIT_OK;
}

// free allocated space for string content
void str_free(string_t *str) {
    if(str->ptr) {
        free(str->ptr);
    }
}

int str_append_strings(string_t *dst, string_t *src) {
    for (unsigned int i = 0; i < src->length; i++) {
        if (str_append_char(dst, *(src->ptr + i))) {
            return E_INT;
        }
    }
    return EXIT_OK;
}

// assigns base16 decoded src to dst
int str_base16_decode(string_t *src, string_t *dst) {
    if (str_create_empty(dst)) return E_INT;
    char c;
    for (unsigned long i = 0; i < src->length; i += 2) {
        // concatenate two chars into one
        c = (char)(((((int)src->ptr[i]) - 'a') * 16 ) + (int)src->ptr[i+1] - 'a');
        if (str_append_char(dst, c)) return E_INT;
    }
    return EXIT_OK;
}

// assigns base16 encoded src to dst
int str_base16_encode(string_t *src, string_t *dst) {
    if (str_create_empty(dst)) return E_INT;

    char *c;
    for (unsigned long i = 0; i < src->length; i++) {
        c = &src->ptr[i];
        // split one char into two
        if (str_append_char(dst, (char)(((unsigned char)(*c) >> 4) + 'a'))) return E_INT;
        if (str_append_char(dst, (char)((unsigned char)(*c & 0x0f) + 'a'))) return E_INT;
    }
    return EXIT_OK;
}

// returns DNS formatted string in dst
int str_base_host_label_format(string_t *src, string_t *dst) {
    int p, i;
    int count;

    // append a dot at the end
    if (*(src->ptr + src->length - 1) != '.') {
        if (str_append_char(src, '.')) return E_INT;
    }

    for(i = 0; i < src->length; i++) {
        if(src->ptr[i] == '.') {
            p = i + 1;
            count = 0;
            while(src->ptr[p] != '.' && src->ptr[p] != '\0') {
                p++;
                count++;
            }
            // add label one octet number at the beginning
            if (str_append_char(dst, (char)(count))) return E_INT;
            continue;
        }
        if (str_append_char(dst, src->ptr[i])) return E_INT;
    }
    return EXIT_OK;
}

// copies NULL terminated content in buffer
void str_copy_to_buffer(string_t *src, unsigned char *buffer) {
    memcpy(buffer, src->ptr, src->length);
    buffer[src->length] = '\0';
}