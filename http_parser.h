#ifndef http_parser_h
#define http_parser_h
#ifdef __cplusplus
extern "C" {
#endif

#ifdef _MSC_VER
#  include <stddef.h>
#endif
#include <sys/types.h>

typedef struct http_parser http_parser;

/* Callbacks should return non-zero to indicate an error. The parse will
 * then halt execution.
 *
 * http_data_cb does not return data chunks. It will be call arbitrarally
 * many times for each string. E.G. you might get 10 callbacks for "on_path"
 * each providing just a few characters more data.
 */
typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);
typedef int (*http_cb) (http_parser*);

/* Request Methods */
enum http_method
  { HTTP_DELETE    = 0x0002
  , HTTP_GET       = 0x0004
  , HTTP_HEAD      = 0x0008
  , HTTP_POST      = 0x0100
  , HTTP_PUT       = 0x0800
  };

enum http_parser_type { HTTP_REQUEST, HTTP_RESPONSE };

struct http_parser {
  /** PRIVATE **/
  int state;
  int header_state;
  size_t header_index;
  enum http_parser_type type;

  size_t chunk_size;
  char flags;

  size_t body_read;

  const char *header_field_mark;
  size_t      header_field_size;
  const char *header_value_mark;
  size_t      header_value_size;
  const char *query_string_mark;
  size_t      query_string_size;
  const char *path_mark;
  size_t      path_size;
  const char *uri_mark;
  size_t      uri_size;
  const char *fragment_mark;
  size_t      fragment_size;

  /** READ-ONLY **/
  unsigned short status_code; /* responses only */
  enum http_method method;    /* requests only */

  int http_major;
  int http_minor;

  short keep_alive;
  ssize_t content_length;

  /** PUBLIC **/
  void *data; /* A pointer to get hook to the "connection" or "socket" object */

  /* an ordered list of callbacks */

  http_cb      on_message_begin;

  /* requests only */
  http_data_cb on_path;
  http_data_cb on_query_string;
  http_data_cb on_uri;
  http_data_cb on_fragment;

  http_data_cb on_header_field;
  http_data_cb on_header_value;
  http_cb      on_headers_complete;
  http_data_cb on_body;
  http_cb      on_message_complete;
};

/* Initializes an http_parser structure.  The second argument specifies if
 * it will be parsing requests or responses.
 */
void http_parser_init (http_parser *parser, enum http_parser_type);

size_t http_parser_execute (http_parser *parser, const char *data, size_t len);

/*
int http_parser_has_error (http_parser *parser);
*/

static inline int
http_parser_should_keep_alive (http_parser *parser)
{
  if (parser->keep_alive == -1) return (parser->http_major == 1 && parser->http_minor == 1);
  return parser->keep_alive;
}


#ifdef __cplusplus
}
#endif
#endif
