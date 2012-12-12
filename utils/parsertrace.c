/* Dump what the parser finds to stdout as it happen */

#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "../http_parser.h"

int on_message_begin(http_parser *_ __attribute__((unused))) {
	printf("\n***MESSAGE BEGIN***\n\n");
	return 0;
}

int on_headers_complete(http_parser *_ __attribute__((unused))) {
	printf("\n***HEADERS COMPLETE***\n\n");
	return 0;
}

int on_message_complete(http_parser *_ __attribute__((unused))) {
	printf("\n***MESSAGE COMPLETE***\n\n");
	return 0;
}

int on_url(http_parser *_ __attribute__((unused)), const char *at, size_t length) {
	printf("Url: %.*s\n", (int)length, at);
	return 0;
}

int on_header_field(http_parser *_ __attribute__((unused)), const char *at, size_t length) {
	printf("Header field: %.*s\n", (int)length, at);
	return 0;
}

int on_header_value(http_parser *_ __attribute__((unused)), const char *at, size_t length) {
	printf("Header value: %.*s\n", (int)length, at);
	return 0;
}

int on_body(http_parser *_ __attribute__((unused)), const char *at, size_t length) {
	printf("Body: %.*s\n", (int)length, at);
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: ./parsertrace $filename\n");
		return EXIT_FAILURE;
	}
	char *filename = argv[1];
	int fd = open(filename, O_RDONLY);

	http_parser_settings settings;
	settings.on_message_begin = on_message_begin;
	settings.on_url = on_url;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;
	settings.on_headers_complete = on_headers_complete;
	settings.on_body = on_body;
	settings.on_message_complete = on_message_complete;
	http_parser *parser = malloc(sizeof(http_parser));
	http_parser_init(parser, HTTP_RESPONSE);

	struct stat statinfo;
	if(stat(argv[1], &statinfo)) {
		fprintf(stderr, "can't stat file\n");
		return EXIT_FAILURE;
	}

	char *data = malloc(statinfo.st_size);
	if(read(fd, data, statinfo.st_size) != statinfo.st_size) {
		fprintf(stderr, "couldn't read entire file (please report this as a bug!)\n");
		return EXIT_FAILURE;
	}

	http_parser_execute(parser, &settings, data, statinfo.st_size);

	return EXIT_SUCCESS;
}
