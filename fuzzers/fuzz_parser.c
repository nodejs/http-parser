#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "http_parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    // prepare a null-terminated string.
    char *new_str = (char *)malloc(size+1);
    if (new_str == NULL){
        return 0;
    }
    memcpy(new_str, data, size);
    new_str[size] = '\0';

    // http-parser logic
    static http_parser_settings settings_null = {
        .on_message_begin = 0
        ,.on_header_field = 0
        ,.on_header_value = 0
        ,.on_url = 0
        ,.on_status = 0
        ,.on_body = 0
        ,.on_headers_complete = 0
        ,.on_message_complete = 0
        ,.on_chunk_header = 0
        ,.on_chunk_complete = 0
    };

    http_parser parser;
    http_parser_init(&parser, HTTP_BOTH);
    http_parser_execute(&parser, &settings_null, new_str, strlen(new_str));

	free(new_str);
	return 0;
}

