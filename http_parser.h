/* Copyright 2009,2010 Ryan Dahl <ry@tinyclouds.org>
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
#ifndef http_parser_h
#define http_parser_h
#ifdef __cplusplus
extern "C" {
#endif


#include <sys/types.h>
#if defined(_WIN32) && !defined(__MINGW32__)
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;

typedef unsigned int size_t;
typedef int ssize_t;
#else
#include <stdint.h>
#endif

/* Compile with -DHTTP_PARSER_STRICT=0 to make less checks, but run
 * faster
 */
#ifndef HTTP_PARSER_STRICT
# define HTTP_PARSER_STRICT 1
#else
# define HTTP_PARSER_STRICT 0
#endif


/* Maximium header size allowed */
#define HTTP_MAX_HEADER_SIZE (80*1024)


typedef struct http_parser http_parser;


/* Request Methods */
enum http_method
  { HTTP_DELETE    = 0
  , HTTP_GET
  , HTTP_HEAD
  , HTTP_POST
  , HTTP_PUT
  /* pathological */
  , HTTP_CONNECT
  , HTTP_OPTIONS
  , HTTP_TRACE
  /* webdav */
  , HTTP_COPY
  , HTTP_LOCK
  , HTTP_MKCOL
  , HTTP_MOVE
  , HTTP_PROPFIND
  , HTTP_PROPPATCH
  , HTTP_UNLOCK
  /* subversion */
  , HTTP_REPORT
  , HTTP_MKACTIVITY
  , HTTP_CHECKOUT
  , HTTP_MERGE
  /* upnp */
  , HTTP_MSEARCH
  , HTTP_NOTIFY
  , HTTP_SUBSCRIBE
  , HTTP_UNSUBSCRIBE
  };


enum http_parser_type { HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH };


struct http_parser {
  /** PRIVATE **/
  unsigned char type : 2;
  unsigned char flags : 6;
  unsigned char state;
  unsigned char header_state;
  unsigned char index;

  uint32_t nread;
  int64_t content_length;

  /** READ-ONLY **/
  unsigned short http_major;
  unsigned short http_minor;
  unsigned short status_code; /* responses only */
  unsigned char method;    /* requests only */

  /* 1 = Upgrade header was present and the parser has exited because of that.
   * 0 = No upgrade header present.
   * Should be checked when http_parser_execute() returns in addition to
   * error checking.
   */
  char upgrade;

  /** PUBLIC **/
  void *data; /* A pointer to get hook to the "connection" or "socket" object */
};


void http_parser_init(http_parser *parser, enum http_parser_type type);


/* If http_should_keep_alive() in the on_headers_complete or
 * on_message_complete callback returns true, then this will be should be
 * the last message on the connection.
 * If you are the server, respond with the "Connection: close" header.
 * If you are the client, close the connection.
 */
int http_should_keep_alive(http_parser *parser);


/* Returns a string version of the HTTP method. */
const char *http_method_str(enum http_method);




/********* Parser Interface 1 *********/
/* For those who like callbacks       */


/* Callbacks should return non-zero to indicate an error. The parser will
 * then halt execution.
 *
 * The one exception is on_headers_complete. In a HTTP_RESPONSE parser
 * returning '1' from on_headers_complete will tell the parser that it
 * should not expect a body. This is used when receiving a response to a
 * HEAD request which may contain 'Content-Length' or 'Transfer-Encoding:
 * chunked' headers that indicate the presence of a body.
 *
 * http_data_cb does not return data chunks. It will be call arbitrarally
 * many times for each string. E.G. you might get 10 callbacks for "on_path"
 * each providing just a few characters more data.
 */
typedef int (*http_data_cb) (http_parser*, const char *at, size_t length);
typedef int (*http_cb) (http_parser*);
typedef struct http_parser_settings http_parser_settings;

struct http_parser_settings {
  http_cb      on_message_begin;
  http_data_cb on_path;
  http_data_cb on_query_string;
  http_data_cb on_url;
  http_data_cb on_fragment;
  http_data_cb on_header_field;
  http_data_cb on_header_value;
  http_cb      on_headers_complete;
  http_data_cb on_body;
  http_cb      on_message_complete;
};

size_t http_parser_execute(http_parser *parser,
                           const http_parser_settings *settings,
                           const char *buf,
                           size_t buf_len);




/********** Parser Interface 2 **********/
/** For those who don't like callbacks **/
/****************************************/


typedef struct http_parser_data http_parser_data;

struct http_parser_data {
  enum { HTTP_PARSER_ERROR = 0
       , HTTP_NEEDS_INPUT
       , HTTP_NEEDS_DATA_ELEMENTS
       , HTTP_REQ_MESSAGE_START   /* payload.method */
       , HTTP_RES_MESSAGE_START   /* payload.status */
       , HTTP_VERSION             /* payload.version */
       , HTTP_PATH                /* payload.string */
       , HTTP_QUERY_STRING        /* payload.string */
       , HTTP_URL                 /* payload.string */
       , HTTP_FRAGMENT            /* payload.string */
       , HTTP_HEADER_FIELD        /* payload.string */
       , HTTP_HEADER_VALUE        /* payload.string */
       , HTTP_HEADERS_END         /* payload.flags */
       , HTTP_BODY                /* payload.string */
       , HTTP_MESSAGE_END         /* payload.string */
       } type;

  union {
    struct {
      const char *p;
      size_t len;
    } string;

    /* For HTTP_RES_MESSAGE_START */
    unsigned short status_code;

    /* For HTTP_REQ_MESSAGE_START */
    unsigned char method;

    /* For HTTP_VERSION */
    struct {
      unsigned short major;
      unsigned short minor;
    } version;

    /* For HTTP_HEADERS_END */
    unsigned char flags : 6;

  } payload;

};

/* Returns the number of elements filled into `data`.
 *
 * Normally `http_parser_execute2` will parse the entire `buf` and fill
 * `data` with elements. Under several conditions `http_parser_execute2` may
 * drop out early. 
 *
 *   1. A parse error was encountered. The last element of data will be
 *      HTTP_PARSER_ERROR. The parser cannot continue further. The
 *      connection to the peer should be severed.
 *
 *   2. The parser still to parser more of `buf` but it has run out of
 *      space in the user-supplied `http_parser_data` array. The last
 *      element of `data` will be HTTP_NEEDS_DATA_ELEMENTS. Restart
 *      http_parser_execute2() with a fresh array of elements starting at
 *      the place that HTTP_NEEDS_DATA_ELEMENTS pointed to.
 *
 *   3. The parser cannot continue until http_parser_has_body(parser, 1) 
 *      or http_parser_has_body(parser, 0) is called. This is required for
 *      all HTTP responses. For the parser it is unclear from the headers if
 *      a response message has a body or not. For example, if the message is
 *      a response to a HEAD request, then it MUST NOT have a body but
 *      nevertheless may contain "Content-Length" or
 *      "Tranfer-Encoding: chunked" headers (which normally indicate the
 *      presence of a body to the parser).
 *
 *      The last element of `data` will be HTTP_NEEDS_INPUT. The user must
 *      call http_parser_has_body() and then restart http_parser_execute2
 *      with a fresh array of `data` elements and starting at the place
 *      HTTP_NEEDS_INPUT pointed to.
 */
int http_parser_execute2(http_parser* parser,
                         const char* buf,
                         size_t buf_len,
                         http_parser_data data[],
                         int data_len);

void http_parser_has_body(http_parser* parser, int);

#ifdef __cplusplus
}
#endif
#endif
