/* Based on src/http/ngx_http_parse.c from NGINX copyright Igor Sysoev
 *
 * Additional changes are licensed under the same terms as NGINX and
 * copyright Joyent, Inc. and other Node contributors. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

/* Dump what the parser finds to stderr as it happen, body go to stdout */

#define _GNU_SOURCE 1
#include "http_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

struct timeval start;
unsigned long long timestamp() {
  struct timeval stop;
  gettimeofday(&stop, NULL);
  return (stop.tv_sec - start.tv_sec)*1000 + (stop.tv_usec - start.tv_usec)/1000;
}

int log_event(const char *fmt, ...) {
  va_list ap;
  char *nfmt;
  va_start(ap, fmt);
  if (asprintf(&nfmt, "%s %6llu ms: %s %s\n",
               isatty(STDERR_FILENO)?"\033[1;33m**":"\n**", timestamp(),
               fmt, isatty(STDERR_FILENO)?"\033[0m":"**\n") == -1) {
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
  } else {
    vfprintf(stderr, nfmt, ap);
    free(nfmt);
  }
  fflush(stderr);
  return 0;
}

int on_message_begin(http_parser* _) {
  (void)_;
  return log_event("MESSAGE BEGIN");
}

int on_headers_complete(http_parser* _) {
  (void)_;
  return log_event("HEADERS COMPLETE");
}

int on_message_complete(http_parser* _) {
  (void)_;
  return log_event("MESSAGE COMPLETE");
}

int on_chunk_begin(http_parser* _) {
  (void)_;
  return log_event("CHUNK BEGIN");
}

int on_chunk_complete(http_parser* _) {
  (void)_;
  return log_event("CHUNK COMPLETE");
}

int on_url(http_parser* _, const char* at, size_t length) {
  (void)_;
  return log_event("URL: %.*s", (int)length, at);
}

int on_header_field(http_parser* _, const char* at, size_t length) {
  (void)_;
  return log_event("Header field: %.*s", (int)length, at);
}

int on_header_value(http_parser* _, const char* at, size_t length) {
  (void)_;
  return log_event("Header value: %.*s", (int)length, at);
}

int on_body(http_parser* _, const char* at, size_t length) {
  (void)_;
  log_event("<body> (size=%zu)", length);
  printf("%.*s", (int)length, at);
  return log_event("</body>");
}

void usage(const char* name) {
  fprintf(stderr,
          "Usage: %s $type $filename\n"
          "  type: -x, where x is one of {r,b,q}\n"
          "  parses file as a Response, reQuest, or Both\n",
          name);
  exit(EXIT_FAILURE);
}

int main(int argc, char* argv[]) {
  char data[2 << 16];
  enum http_parser_type file_type;

  if (argc != 3) {
    usage(argv[0]);
  }

  char* type = argv[1];
  if (type[0] != '-') {
    usage(argv[0]);
  }

  switch (type[1]) {
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
      usage(argv[0]);
  }

  char* filename = argv[2];
  FILE* file = (strcmp(filename, "-"))?fopen(filename, "r"):stdin;
  if (file == NULL) {
    perror("fopen");
    return EXIT_FAILURE;
  }

  http_parser_settings settings;
  memset(&settings, 0, sizeof(settings));
  settings.on_message_begin = on_message_begin;
  settings.on_url = on_url;
  settings.on_header_field = on_header_field;
  settings.on_header_value = on_header_value;
  settings.on_headers_complete = on_headers_complete;
  settings.on_chunk_begin = on_chunk_begin;
  settings.on_body = on_body;
  settings.on_chunk_complete = on_chunk_complete;
  settings.on_message_complete = on_message_complete;

  http_parser parser;
  http_parser_init(&parser, file_type);
  gettimeofday(&start, NULL);

  size_t len;
  while ((len = fread(data, 1, sizeof(data), file)) > 0) {
    size_t nparsed = http_parser_execute(&parser, &settings, data, len);
    if (nparsed != len) {
      fprintf(stderr,
              "Error: %s (%s)\n",
              http_errno_description(HTTP_PARSER_ERRNO(&parser)),
              http_errno_name(HTTP_PARSER_ERRNO(&parser)));
      if (file != stdin) fclose(file);
      return EXIT_FAILURE;
    }
  }

  if (file != stdin) fclose(file);
  return EXIT_SUCCESS;
}
