/* Dump what the parser finds to stdout as it happen */

#include <stdio.h>
#include <stdlib.h>
#include "../http_parser.h"

int on_message_begin(http_parser *_ ) {
	(void)_;
	printf("\n***MESSAGE BEGIN***\n\n");
	return 0;
}

int on_headers_complete(http_parser *_ ) {
	(void)_;
	printf("\n***HEADERS COMPLETE***\n\n");
	return 0;
}

int on_message_complete(http_parser *_ ) {
	(void)_;
	printf("\n***MESSAGE COMPLETE***\n\n");
	return 0;
}

int on_url(http_parser *_ , const char *at, size_t length) {
	(void)_;
	printf("Url: %.*s\n", (int)length, at);
	return 0;
}

int on_header_field(http_parser *_ , const char *at, size_t length) {
	(void)_;
	printf("Header field: %.*s\n", (int)length, at);
	return 0;
}

int on_header_value(http_parser *_ , const char *at, size_t length) {
	(void)_;
	printf("Header value: %.*s\n", (int)length, at);
	return 0;
}

int on_body(http_parser *_ , const char *at, size_t length) {
	(void)_;
	printf("Body: %.*s\n", (int)length, at);
	return 0;
}

int main(int argc, char *argv[]) {
	enum http_parser_type file_type;
	if (argc != 3) {
err:		fprintf(stderr, "Usage: %s $type $filename\n"
						"\ttype: -x, where x is one of {r,b,q}\n"
						"\tparses file a Response, reQuest, or Both\n"
						, argv[0]);
		return EXIT_FAILURE;
	}
	char *type = argv[1];
	if (type[0] != '-') {
		goto err;
	} else {
		switch(type[1]) {
			/* in the case of "-", type[1] will be NUL */
			case 'r':
				file_type = HTTP_RESPONSE;
				break;
			case 'q':
				file_type = HTTP_REQUEST;
				break;
			case 'b':
				file_type = HTTP_BOTH;
				break;
			default:
				goto err;
				break;
		}
	}
	char *filename = argv[2];
	FILE *file = fopen(filename, "r");
	if (file == NULL) {
		fprintf(stderr, "Error: couldn't open %s\n", filename);
		return EXIT_FAILURE;
	}

	fseek(file, 0, SEEK_END);
	unsigned long file_length = (unsigned long)ftell(file);
    fseek(file, 0, SEEK_SET);

	char *data = malloc(file_length);
	if(fread(data, sizeof(char), file_length, file) != file_length) {
		fprintf(stderr, "couldn't read entire file (please report this as a bug!)\n");
		return EXIT_FAILURE;
	}

	http_parser_settings settings;
	settings.on_message_begin = on_message_begin;
	settings.on_url = on_url;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;
	settings.on_headers_complete = on_headers_complete;
	settings.on_body = on_body;
	settings.on_message_complete = on_message_complete;
	http_parser parser;
	http_parser_init(&parser, file_type);

	if (http_parser_execute(&parser, &settings, data, file_length) != file_length) {
		fprintf(stderr, "Error: %s (%s)\n",
				http_errno_description(HTTP_PARSER_ERRNO(&parser)),
				http_errno_name(HTTP_PARSER_ERRNO(&parser)));
	}

	free(data);
	return EXIT_SUCCESS;
}
