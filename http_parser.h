/*
Mongrel Web Server (Mongrel) is copyrighted free software by Zed A. Shaw
<zedshaw at zedshaw dot com> and contributors.

This source file is based on Mongrel's parser. Changes by Ryan Dahl
<ry@tinyclouds.org> in 2008 and 2009.

You can redistribute it and/or modify it under either the terms of the GPL2
or the conditions below:

1. You may make and give away verbatim copies of the source form of the
   software without restriction, provided that you duplicate all of the
   original copyright notices and associated disclaimers.

2. You may modify your copy of the software in any way, provided that
   you do at least ONE of the following:

     a) place your modifications in the Public Domain or otherwise make them
     Freely Available, such as by posting said modifications to Usenet or an
     equivalent medium, or by allowing the author to include your
     modifications in the software.

     b) use the modified software only within your corporation or
        organization.

     c) rename any non-standard executables so the names do not conflict with
     standard executables, which must also be provided.

     d) make other distribution arrangements with the author.

3. You may distribute the software in object code or executable
   form, provided that you do at least ONE of the following:

     a) distribute the executables and library files of the software,
     together with instructions (in the manual page or equivalent) on where
     to get the original distribution.

     b) accompany the distribution with the machine-readable source of the
     software.

     c) give non-standard executables non-standard names, with
        instructions on where to get the original software distribution.

     d) make other distribution arrangements with the author.

4. You may modify and include the part of the software into any other
   software (possibly commercial).  But some files in the distribution
   are not written by the author, so that they are not under this terms.

5. The scripts and library files supplied as input to or produced as
   output from the software do not automatically fall under the
   copyright of the software, but belong to whomever generated them,
   and may be sold commercially, and may be aggregated with this
   software.

6. THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR
   IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.
*/
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
  { HTTP_COPY      = 0x0001
  , HTTP_DELETE    = 0x0002
  , HTTP_GET       = 0x0004
  , HTTP_HEAD      = 0x0008
  , HTTP_LOCK      = 0x0010
  , HTTP_MKCOL     = 0x0020
  , HTTP_MOVE      = 0x0040
  , HTTP_OPTIONS   = 0x0080
  , HTTP_POST      = 0x0100
  , HTTP_PROPFIND  = 0x0200
  , HTTP_PROPPATCH = 0x0400
  , HTTP_PUT       = 0x0800
  , HTTP_TRACE     = 0x1000
  , HTTP_UNLOCK    = 0x2000
  };

enum http_parser_type { HTTP_REQUEST, HTTP_RESPONSE };

enum http_version
  { HTTP_VERSION_OTHER  = 0x00
  , HTTP_VERSION_11     = 0x01
  , HTTP_VERSION_10     = 0x02
  , HTTP_VERSION_09     = 0x04
  };

struct http_parser {
  /** PRIVATE **/
  int cs;
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
  enum http_version version;
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

void http_parser_execute (http_parser *parser, const char *data, size_t len);

int http_parser_has_error (http_parser *parser);

static inline int
http_parser_should_keep_alive (http_parser *parser)
{
  if (parser->keep_alive == -1) return (parser->version == HTTP_VERSION_11);
  return parser->keep_alive;
}


#ifdef __cplusplus
}
#endif
#endif
