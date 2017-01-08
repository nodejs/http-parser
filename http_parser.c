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
#include "http_parser.h"
#include <assert.h>
#include <stddef.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#ifndef ULLONG_MAX
# define ULLONG_MAX ((uint64_t) -1) /* 2^64-1 */
#endif

#ifndef MIN
# define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef ARRAY_SIZE
# define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef BIT_AT
# define BIT_AT(a, i)                                                \
  (!!((unsigned int) (a)[(unsigned int) (i) >> 3] &                  \
   (1 << ((unsigned int) (i) & 7))))
#endif

#ifndef ELEM_AT
# define ELEM_AT(a, i, v) ((unsigned int) (i) < ARRAY_SIZE(a) ? (a)[(i)] : (v))
#endif

#define SET_ERRNO(e)                                                 \
do {                                                                 \
  parser->http_errno = (e);                                          \
} while(0)

#define CURRENT_STATE() p_state
#define UPDATE_STATE(V) p_state = (enum state) (V);
#define RETURN(V)                                                    \
do {                                                                 \
  parser->state = CURRENT_STATE();                                   \
  return (V);                                                        \
} while (0);
#define REEXECUTE()                                                  \
  goto reexecute;                                                    \


#ifdef __GNUC__
# define LIKELY(X) __builtin_expect(!!(X), 1)
# define UNLIKELY(X) __builtin_expect(!!(X), 0)
#else
# define LIKELY(X) (X)
# define UNLIKELY(X) (X)
#endif


/* Run the notify callback FOR, returning ER if it fails */
#define CALLBACK_NOTIFY_(FOR, ER)                                    \
do {                                                                 \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if (LIKELY(settings->on_##FOR)) {                                  \
    parser->state = CURRENT_STATE();                                 \
    if (UNLIKELY(0 != settings->on_##FOR(parser))) {                 \
      SET_ERRNO(HPE_CB_##FOR);                                       \
    }                                                                \
    UPDATE_STATE(parser->state);                                     \
                                                                     \
    /* We either errored above or got paused; get out */             \
    if (UNLIKELY(HTTP_PARSER_ERRNO(parser) != HPE_OK)) {             \
      return (ER);                                                   \
    }                                                                \
  }                                                                  \
} while (0)

/* Run the notify callback FOR and consume the current byte */
#define CALLBACK_NOTIFY(FOR)            CALLBACK_NOTIFY_(FOR, p - data + 1)

/* Run the notify callback FOR and don't consume the current byte */
#define CALLBACK_NOTIFY_NOADVANCE(FOR)  CALLBACK_NOTIFY_(FOR, p - data)

/* Run data callback FOR with LEN bytes, returning ER if it fails */
#define CALLBACK_DATA_(FOR, LEN, ER)                                 \
do {                                                                 \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if (FOR##_mark) {                                                  \
    if (LIKELY(settings->on_##FOR)) {                                \
      parser->state = CURRENT_STATE();                               \
      if (UNLIKELY(0 !=                                              \
                   settings->on_##FOR(parser, FOR##_mark, (LEN)))) { \
        SET_ERRNO(HPE_CB_##FOR);                                     \
      }                                                              \
      UPDATE_STATE(parser->state);                                   \
                                                                     \
      /* We either errored above or got paused; get out */           \
      if (UNLIKELY(HTTP_PARSER_ERRNO(parser) != HPE_OK)) {           \
        return (ER);                                                 \
      }                                                              \
    }                                                                \
    FOR##_mark = NULL;                                               \
  }                                                                  \
} while (0)

/* Run the data callback FOR and consume the current byte */
#define CALLBACK_DATA(FOR)                                           \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data + 1)

/* Run the data callback FOR and don't consume the current byte */
#define CALLBACK_DATA_NOADVANCE(FOR)                                 \
    CALLBACK_DATA_(FOR, p - FOR##_mark, p - data)

/* Set the mark FOR; non-destructive if mark is already set */
#define MARK(FOR)                                                    \
do {                                                                 \
  if (!FOR##_mark) {                                                 \
    FOR##_mark = p;                                                  \
  }                                                                  \
} while (0)

/* Don't allow the total size of the HTTP headers (including the status
 * line) to exceed HTTP_MAX_HEADER_SIZE.  This check is here to protect
 * embedders against denial-of-service attacks where the attacker feeds
 * us a never-ending header that the embedder keeps buffering.
 *
 * This check is arguably the responsibility of embedders but we're doing
 * it on the embedder's behalf because most won't bother and this way we
 * make the web a little safer.  HTTP_MAX_HEADER_SIZE is still far bigger
 * than any reasonable request or response so this should never affect
 * day-to-day operation.
 */
#define COUNT_HEADER_SIZE(V)                                         \
do {                                                                 \
  parser->nread += (V);                                              \
  if (UNLIKELY(parser->nread > (HTTP_MAX_HEADER_SIZE))) {            \
    SET_ERRNO(HPE_HEADER_OVERFLOW);                                  \
    goto error;                                                      \
  }                                                                  \
} while (0)


#define PROXY_CONNECTION "proxy-connection"
#define CONNECTION "connection"
#define CONTENT_LENGTH "content-length"
#define TRANSFER_ENCODING "transfer-encoding"
#define UPGRADE "upgrade"
#define CHUNKED "chunked"
#define KEEP_ALIVE "keep-alive"
#define CLOSE "close"


static const char *method_strings[] =
  {
#define XX(num, name, string) #string,
  HTTP_METHOD_MAP(XX)
#undef XX
  };


/* Tokens as defined by rfc 2616. Also lowercases them.
 *        token       = 1*<any CHAR except CTLs or separators>
 *     separators     = "(" | ")" | "<" | ">" | "@"
 *                    | "," | ";" | ":" | "\" | <">
 *                    | "/" | "[" | "]" | "?" | "="
 *                    | "{" | "}" | SP | HT
 */
static const char tokens[256] = {
/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
        0,       0,       0,       0,       0,       0,       0,       0,
/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
        0,      '!',      0,      '#',     '$',     '%',     '&',    '\'',
/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
        0,       0,      '*',     '+',      0,      '-',     '.',      0,
/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
       '0',     '1',     '2',     '3',     '4',     '5',     '6',     '7',
/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
       '8',     '9',      0,       0,       0,       0,       0,       0,
/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
        0,      'a',     'b',     'c',     'd',     'e',     'f',     'g',
/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
       'x',     'y',     'z',      0,       0,       0,      '^',     '_',
/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
       '`',     'a',     'b',     'c',     'd',     'e',     'f',     'g',
/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
       'h',     'i',     'j',     'k',     'l',     'm',     'n',     'o',
/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
       'p',     'q',     'r',     's',     't',     'u',     'v',     'w',
/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
       'x',     'y',     'z',      0,      '|',      0,      '~',       0 };


static const int8_t unhex[256] =
  {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  , 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1
  ,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
  };


#if HTTP_PARSER_STRICT
# define T(v) 0
#else
# define T(v) v
#endif


static const uint8_t normal_url_char[32] = {
/*   0 nul    1 soh    2 stx    3 etx    4 eot    5 enq    6 ack    7 bel  */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*   8 bs     9 ht    10 nl    11 vt    12 np    13 cr    14 so    15 si   */
        0    | T(2)   |   0    |   0    | T(16)  |   0    |   0    |   0,
/*  16 dle   17 dc1   18 dc2   19 dc3   20 dc4   21 nak   22 syn   23 etb */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*  24 can   25 em    26 sub   27 esc   28 fs    29 gs    30 rs    31 us  */
        0    |   0    |   0    |   0    |   0    |   0    |   0    |   0,
/*  32 sp    33  !    34  "    35  #    36  $    37  %    38  &    39  '  */
        0    |   2    |   4    |   0    |   16   |   32   |   64   |  128,
/*  40  (    41  )    42  *    43  +    44  ,    45  -    46  .    47  /  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  48  0    49  1    50  2    51  3    52  4    53  5    54  6    55  7  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  56  8    57  9    58  :    59  ;    60  <    61  =    62  >    63  ?  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |   0,
/*  64  @    65  A    66  B    67  C    68  D    69  E    70  F    71  G  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  72  H    73  I    74  J    75  K    76  L    77  M    78  N    79  O  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  80  P    81  Q    82  R    83  S    84  T    85  U    86  V    87  W  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  88  X    89  Y    90  Z    91  [    92  \    93  ]    94  ^    95  _  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/*  96  `    97  a    98  b    99  c   100  d   101  e   102  f   103  g  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 104  h   105  i   106  j   107  k   108  l   109  m   110  n   111  o  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 112  p   113  q   114  r   115  s   116  t   117  u   118  v   119  w  */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |  128,
/* 120  x   121  y   122  z   123  {   124  |   125  }   126  ~   127 del */
        1    |   2    |   4    |   8    |   16   |   32   |   64   |   0, };

#undef T

enum state
  { s_dead = 1 /* important that this is > 0 */

  , s_start_req_or_res
  , s_res_or_resp_H
  , s_start_res
  , s_res_H
  , s_res_HT
  , s_res_HTT
  , s_res_HTTP
  , s_res_first_http_major
  , s_res_http_major
  , s_res_first_http_minor
  , s_res_http_minor
  , s_res_first_status_code
  , s_res_status_code
  , s_res_status_start
  , s_res_status
  , s_res_line_almost_done

  , s_start_req

  , s_req_method
  , s_req_spaces_before_url
  , s_req_schema
  , s_req_schema_slash
  , s_req_schema_slash_slash
  , s_req_server_start
  , s_req_server
  , s_req_server_with_at
  , s_req_path
  , s_req_query_string_start
  , s_req_query_string
  , s_req_fragment_start
  , s_req_fragment
  , s_req_http_start
  , s_req_http_H
  , s_req_http_HT
  , s_req_http_HTT
  , s_req_http_HTTP
  , s_req_first_http_major
  , s_req_http_major
  , s_req_first_http_minor
  , s_req_http_minor
  , s_req_line_almost_done

  , s_header_field_start
  , s_header_field
  , s_header_value_discard_ws
  , s_header_value_discard_ws_almost_done
  , s_header_value_discard_lws
  , s_header_value_start
  , s_header_value
  , s_header_value_lws

  , s_header_almost_done

  , s_chunk_size_start
  , s_chunk_size
  , s_chunk_parameters
  , s_chunk_size_almost_done

  , s_headers_almost_done
  , s_headers_done

  /* Important: 's_headers_done' must be the last 'header' state. All
   * states beyond this must be 'body' states. It is used for overflow
   * checking. See the PARSING_HEADER() macro.
   */

  , s_chunk_data
  , s_chunk_data_almost_done
  , s_chunk_data_done

  , s_body_identity
  , s_body_identity_eof

  , s_message_done
  };


#define PARSING_HEADER(state) (state <= s_headers_done)


enum header_states
  { h_general = 0
  , h_C
  , h_CO
  , h_CON

  , h_matching_connection
  , h_matching_proxy_connection
  , h_matching_content_length
  , h_matching_transfer_encoding
  , h_matching_upgrade

  , h_connection
  , h_content_length
  , h_transfer_encoding
  , h_upgrade

  , h_matching_transfer_encoding_chunked
  , h_matching_connection_token_start
  , h_matching_connection_keep_alive
  , h_matching_connection_close
  , h_matching_connection_upgrade
  , h_matching_connection_token

  , h_transfer_encoding_chunked
  , h_connection_keep_alive
  , h_connection_close
  , h_connection_upgrade
  };

enum http_host_state
  {
    s_http_host_dead = 1
  , s_http_userinfo_start
  , s_http_userinfo
  , s_http_host_start
  , s_http_host_v6_start
  , s_http_host
  , s_http_host_v6
  , s_http_host_v6_end
  , s_http_host_v6_zone_start
  , s_http_host_v6_zone
  , s_http_host_port_start
  , s_http_host_port
};

/* Macros for character classes; depends on strict-mode  */
#define CR                  '\r'
#define LF                  '\n'
#define LOWER(c)            (unsigned char)(c | 0x20)
#define IS_ALPHA(c)         (LOWER(c) >= 'a' && LOWER(c) <= 'z')
#define IS_NUM(c)           ((c) >= '0' && (c) <= '9')
#define IS_ALPHANUM(c)      (IS_ALPHA(c) || IS_NUM(c))
#define IS_HEX(c)           (IS_NUM(c) || (LOWER(c) >= 'a' && LOWER(c) <= 'f'))
#define IS_MARK(c)          ((c) == '-' || (c) == '_' || (c) == '.' || \
  (c) == '!' || (c) == '~' || (c) == '*' || (c) == '\'' || (c) == '(' || \
  (c) == ')')
#define IS_USERINFO_CHAR(c) (IS_ALPHANUM(c) || IS_MARK(c) || (c) == '%' || \
  (c) == ';' || (c) == ':' || (c) == '&' || (c) == '=' || (c) == '+' || \
  (c) == '$' || (c) == ',')

#define STRICT_TOKEN(c)     (tokens[(unsigned char)c])

#if HTTP_PARSER_STRICT
#define TOKEN(c)            (tokens[(unsigned char)c])
#define IS_URL_CHAR(c)      (BIT_AT(normal_url_char, (unsigned char)c))
#define IS_HOST_CHAR(c)     (IS_ALPHANUM(c) || (c) == '.' || (c) == '-')
#else
#define TOKEN(c)            ((c == ' ') ? ' ' : tokens[(unsigned char)c])
#define IS_URL_CHAR(c)                                                         \
  (BIT_AT(normal_url_char, (unsigned char)c) || ((c) & 0x80))
#define IS_HOST_CHAR(c)                                                        \
  (IS_ALPHANUM(c) || (c) == '.' || (c) == '-' || (c) == '_')
#endif

/**
 * Verify that a char is a valid visible (printable) US-ASCII
 * character or %x80-FF
 **/
#define IS_HEADER_CHAR(ch)                                                     \
  (ch == CR || ch == LF || ch == 9 || ((unsigned char)ch > 31 && ch != 127))

#define start_state (parser->type == HTTP_REQUEST ? s_start_req : s_start_res)


#if HTTP_PARSER_STRICT
# define STRICT_CHECK(cond)                                          \
do {                                                                 \
  if (cond) {                                                        \
    SET_ERRNO(HPE_STRICT);                                           \
    goto error;                                                      \
  }                                                                  \
} while (0)
# define NEW_MESSAGE() (http_should_keep_alive(parser) ? start_state : s_dead)
#else
# define STRICT_CHECK(cond)
# define NEW_MESSAGE() start_state
#endif


/* Map errno values to strings for human-readable output */
#define HTTP_STRERROR_GEN(n, s) { "HPE_" #n, s },
static struct {
  const char *name;
  const char *description;
} http_strerror_tab[] = {
  HTTP_ERRNO_MAP(HTTP_STRERROR_GEN)
};
#undef HTTP_STRERROR_GEN

int http_message_needs_eof(const http_parser *parser);

/* Our URL parser.
 *
 * This is designed to be shared by http_parser_execute() for URL validation,
 * hence it has a state transition + byte-for-byte interface. In addition, it
 * is meant to be embedded in http_parser_parse_url(), which does the dirty
 * work of turning state transitions URL components for its API.
 *
 * This function should only be invoked with non-space characters. It is
 * assumed that the caller cares about (and can detect) the transition between
 * URL and non-URL states by looking for these.
 */
static enum state
parse_url_char(enum state s, const char ch)
{
  /* If current character is space, CR, or LF */
  if (ch == ' ' || ch == '\r' || ch == '\n') {
    /* Return dead state */
    return s_dead;
  }
  /* If current character is not space, CR, or LF */

#if HTTP_PARSER_STRICT
  /* If current character is tab or formfeed */
  if (ch == '\t' || ch == '\f') {
    /* Return dead state */
    return s_dead;
  }
  /* If current character is not tab or formfeed */
#endif

  switch (s) {
    /* If current state is request line after met method name, e.g. `GET ` */
    case s_req_spaces_before_url:
      /* Proxied requests are followed by scheme of an absolute URI (alpha).
       * All methods except CONNECT are followed by '/' or '*'.
       */

      /* If current character is `/` or `*` */
      if (ch == '/' || ch == '*') {
        /* Return next state */
        return s_req_path;
      }
      /* If current character is not `/` or `*` */

      /* If current character is alphabetic */
      if (IS_ALPHA(ch)) {
        /* Return next state */
        return s_req_schema;
      }
      /* If current character is not alphabetic */

      /* Break to return dead state */
      break;

    /* If current state is request schema */
    case s_req_schema:
      /* If current character is alphabetic */
      if (IS_ALPHA(ch)) {
        /* Stay in the state */
        return s;
      }
      /* If current character is not alphabetic */

      /* If current character is `:` */
      if (ch == ':') {
        /* Return next state */
        return s_req_schema_slash;
      }
      /* If current character is not `:` */

      /* Break to return dead state */
      break;

    /* If current state is request schema before meet the first slash  */
    case s_req_schema_slash:
      /* If current character is `/` */
      if (ch == '/') {
        /* Return next state */
        return s_req_schema_slash_slash;
      }
      /* If current character is not `/` */

      /* Break to return dead state */
      break;

    /* If current state is request schema before meet the second slash */
    case s_req_schema_slash_slash:
      /* If current character is `/` */
      if (ch == '/') {
        /* Return next state */
        return s_req_server_start;
      }
      /* If current character is not `/` */

      /* Break to return dead state */
      break;

    /* If current state is request server after met `@` */
    case s_req_server_with_at:
      /* If current character is `@` */
      if (ch == '@') {
        /* Return dead state */
        return s_dead;
      }
      /* If current character is not `@` */

    /* FALLTHROUGH */
    /* If current state is request server */
    case s_req_server_start:
    case s_req_server:
      /* If current character is `/`.
       * It means start of request path.
       */
      if (ch == '/') {
        /* Return next state */
        return s_req_path;
      }
      /* If current character is not `/` */

      /* If current character is `?`.
       * It means start of query string.
       */
      if (ch == '?') {
        /* Return next state */
        return s_req_query_string_start;
      }
      /* If current character is not `?` */

      /* If current character is `@` */
      if (ch == '@') {
        /* Return next state */
        return s_req_server_with_at;
      }
      /* If current character is not `@` */

      /* If current character is one of these */
      if (IS_USERINFO_CHAR(ch) || ch == '[' || ch == ']') {
        /* Stay in the state */
        return s_req_server;
      }
      /* If current character is not one of these */

      /* Break to return dead state */
      break;

    /* If current state is request path */
    case s_req_path:
      /* If current character is normal URL character */
      if (IS_URL_CHAR(ch)) {
        /* Stay in the state */
        return s;
      }
      /* If current character is not normal URL character */

      switch (ch) {
        /* If current character is `?`.
         * It means start of query string.
         */
        case '?':
          /* Return next state */
          return s_req_query_string_start;

        /* If current character is `#`.
         * It means start of fragment string.
         */
        case '#':
          /* Return next state */
          return s_req_fragment_start;
      }
      /* If current character is none of above */

      /* Break to return dead state */
      break;

    /* If current state is request query string */
    case s_req_query_string_start:
    case s_req_query_string:
      /* If current character is normal URL character */
      if (IS_URL_CHAR(ch)) {
        /* Stay in the state */
        return s_req_query_string;
      }
      /* If current character is not normal URL character */

      switch (ch) {
        /* If current character is `?`.
         * It means a literal `?`.
         */
        case '?':
          /* Stay in the state */
          /* allow extra '?' in query string */
          return s_req_query_string;

        /* If current character is `#`.
         * It means start of fragment string.
         */
        case '#':
          /* Return next state */
          return s_req_fragment_start;
      }
      /* If current character is none of above */

      /* Break to return dead state */
      break;

    /* If current state is request fragment string start */
    case s_req_fragment_start:
      /* If current character is normal URL character */
      if (IS_URL_CHAR(ch)) {
        /* Return next state */
        return s_req_fragment;
      }
      /* If current character is not normal URL character */

      switch (ch) {
        /* If current character is `?` */
        case '?':
          /* Return next state */
          return s_req_fragment;

        /* If current character is `#` */
        case '#':
          /* Stay in the state */
          return s;
      }
      /* If current character is none of above */

      /* Break to return dead state */
      break;

    /* If current state is fragment string */
    case s_req_fragment:
      /* If current character is normal URL character */
      if (IS_URL_CHAR(ch)) {
        /* Stay in the state */
        return s;
      }
      /* If current character is not normal URL character */

      switch (ch) {
        /* If current character is `?` or `#`.
         * It means a literal `?` or `#`.
         */
        case '?':
        case '#':
          /* Stay in the state */
          return s;
      }
      /* If current character is none of above */

      /* Break to return dead state */
      break;

    /* If current state is none of above */
    default:
      /* Break to return dead state */
      break;
  }

  /* Return dead state */
  /* We should never fall out of the switch above unless there's an error */
  return s_dead;
}

size_t http_parser_execute (http_parser *parser,
                            const http_parser_settings *settings,
                            const char *data,
                            size_t len)
{
  /* c: Current character token.
   * ch: Current character.
   */
  char c, ch;

  /* Chunk size of a request with header `Transfer-Encoding: chunked` */
  int8_t unhex_val;

  /* Current character pointer */
  const char *p = data;

  /* Marked data pointers */
  const char *header_field_mark = 0;
  const char *header_value_mark = 0;
  const char *url_mark = 0;
  const char *body_mark = 0;
  const char *status_mark = 0;

  /* Parser state */
  enum state p_state = (enum state) parser->state;

  /* Whether be lenient on header characters */
  const unsigned int lenient = parser->lenient_http_headers;

  /* If have error */
  /* We're in an error state. Don't bother doing anything. */
  if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
    /* Return parsed number of bytes */
    return 0;
  }

  /* If data length is zero */
  if (len == 0) {
    switch (CURRENT_STATE()) {
      /* If current state is consume remaining data */
      case s_body_identity_eof:
        /* Call callback */
        /* Use of CALLBACK_NOTIFY() here would erroneously return 1 byte read if
         * we got paused.
         */
        CALLBACK_NOTIFY_NOADVANCE(message_complete);

        /* Return parsed number of bytes */
        return 0;

      /* If current state is one of these */
      case s_dead:
      case s_start_req_or_res:
      case s_start_res:
      case s_start_req:
        /* Return parsed number of bytes */
        return 0;

      /* If current state is none of above */
      default:
        /* Set error number */
        SET_ERRNO(HPE_INVALID_EOF_STATE);

        /* Return parsed number of bytes */
        return 1;
    }
  }


  /* If current state is header field */
  if (CURRENT_STATE() == s_header_field)
    /* Set header field mark */
    header_field_mark = data;
  /* If current state is header value */
  if (CURRENT_STATE() == s_header_value)
    /* Set header value mark */
    header_value_mark = data;

  switch (CURRENT_STATE()) {
  /* If current state is one of these */
  case s_req_path:
  case s_req_schema:
  case s_req_schema_slash:
  case s_req_schema_slash_slash:
  case s_req_server_start:
  case s_req_server:
  case s_req_server_with_at:
  case s_req_query_string_start:
  case s_req_query_string:
  case s_req_fragment_start:
  case s_req_fragment:
    /* Set url mark */
    url_mark = data;
    break;
  /* If current state is response line after met the first character of the
   * status message.
   */
  case s_res_status:
    /* Set status mark */
    status_mark = data;
    break;
  default:
    break;
  }

  /* For each character in the data */
  for (p=data; p != data + len; p++) {
    /* Get current character */
    ch = *p;

    /* If current state is parsing header */
    if (PARSING_HEADER(CURRENT_STATE()))
      /* Increase already-read counter `parser->nread`.
       * Ensure the counter is within limit.
       */
      COUNT_HEADER_SIZE(1);

reexecute:
    switch (CURRENT_STATE()) {

      /* If current state is dead state */
      case s_dead:
        /* this state is used after a 'Connection: close' message
         * the parser will error out if it reads another message
         */

        /* If current character is CR or LF */
        if (LIKELY(ch == CR || ch == LF))
          /* Done with current character */
          break;
        /* If current character is not CR or LF */

        /* Set error number */
        SET_ERRNO(HPE_CLOSED_CONNECTION);

        /* Goto error handler */
        goto error;

      /* If current state is start of request or response */
      case s_start_req_or_res:
      {
        /* If current character is CR or LF */
        if (ch == CR || ch == LF)
          /* Done with current character */
          break;
        /* If current character is not CR or LF */

        /* Reset flags */
        parser->flags = 0;

        /* Reset unread content length */
        parser->content_length = ULLONG_MAX;

        /* If current character is `H`.
         * It means start of either request or response.
         */
        if (ch == 'H') {
          /* Update state */
          UPDATE_STATE(s_res_or_resp_H);

          /* Call callback */
          CALLBACK_NOTIFY(message_begin);
        /* If current character is not `H`.
         * It means start of request.
         */
        } else {
          /* Set parser type */
          parser->type = HTTP_REQUEST;

          /* Update state */
          UPDATE_STATE(s_start_req);

          /* Re-parse with new state */
          REEXECUTE();
        }

        /* Done with current character */
        break;
      }

      /* If current state is start of request or response after met `H` */
      case s_res_or_resp_H:
        /* If current character is `T`.
         * It means the method name might be `HTTP`.
         */
        if (ch == 'T') {
          /* Set parser type */
          parser->type = HTTP_RESPONSE;

          /* Update state */
          UPDATE_STATE(s_res_HT);
        /* If current character is not `T`.
         * It means the method name will not be `HTTP`.
         */
        } else {
          /* If current character is not `E`.
           * It means the method name will not be `HEAD`.
           */
          if (UNLIKELY(ch != 'E')) {
            /* Set error number */
            SET_ERRNO(HPE_INVALID_CONSTANT);

            /* Goto error handler */
            goto error;
          }
          /* If current character is `E`.
           * It means the method name might be `HEAD`.
           */

          /* Set parser type */
          parser->type = HTTP_REQUEST;

          /* Set method type */
          parser->method = HTTP_HEAD;

          /* Set parser index */
          parser->index = 2;

          /* Update state */
          UPDATE_STATE(s_req_method);
        }

        /* Done with current character */
        break;

      /* If current state is response line start */
      case s_start_res:
      {
        /* Reset flags */
        parser->flags = 0;

        /* Reset unread content length */
        parser->content_length = ULLONG_MAX;

        switch (ch) {
          /* If current character is `H` */
          case 'H':
            /* Update state */
            UPDATE_STATE(s_res_H);

            /* Done with current character */
            break;

          /* If current character is CR or LF */
          case CR:
          case LF:
            /* Done with current character */
            break;

          /* If current character is none of above */
          default:
            /* Set error number */
            SET_ERRNO(HPE_INVALID_CONSTANT);

            /* Goto error handler */
            goto error;
        }

        /* Call callback */
        CALLBACK_NOTIFY(message_begin);

        /* Done with current character */
        break;
      }

      /* If current state is response line after met `H` */
      case s_res_H:
        /* Ensure current character is `T`.
         * Ensure current characters are `HT`.
         */
        STRICT_CHECK(ch != 'T');

        /* Update state */
        UPDATE_STATE(s_res_HT);

        /* Done with current character */
        break;

      /* If current state is response line after met `HT` */
      case s_res_HT:
        /* Ensure current character is `T`.
         * Ensure current characters are `HTT`.
         */
        STRICT_CHECK(ch != 'T');

        /* Update state */
        UPDATE_STATE(s_res_HTT);

        /* Done with current character */
        break;

      /* If current state is response line after met `HTT` */
      case s_res_HTT:
        /* Ensure current character is `P`.
         * Ensure current characters are `HTTP`.
         */
        STRICT_CHECK(ch != 'P');

        /* Update state */
        UPDATE_STATE(s_res_HTTP);

        /* Done with current character */
        break;

      /* If current state is response line after met `HTTP` */
      case s_res_HTTP:
        /* Ensure current character is `/`.
         * Ensure current characters are `HTTP/`.
         */
        STRICT_CHECK(ch != '/');

        /* Update state */
        UPDATE_STATE(s_res_first_http_major);

        /* Done with current character */
        break;

      /* If current state is response line after met `HTTP/` */
      case s_res_first_http_major:
        /* If current character is not digit */
        if (UNLIKELY(ch < '0' || ch > '9')) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit */

        /* Set HTTP major version */
        parser->http_major = ch - '0';

        /* Update state */
        UPDATE_STATE(s_res_http_major);

        /* Done with current character */
        break;

      /* If current state is response line after met `HTTP/[0-9]` */
      /* major HTTP version or dot */
      case s_res_http_major:
      {
        /* If current character is `.` */
        if (ch == '.') {
          /* Update state */
          UPDATE_STATE(s_res_first_http_minor);

          /* Done with current character */
          break;
        }
        /* If current character is not `.` */

        /* If current character is not digit */
        if (!IS_NUM(ch)) {
          /* Set error */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit.
         * It means one more digit for the HTTP major number.
         */

        /* Update HTTP major number */
        parser->http_major *= 10;
        parser->http_major += ch - '0';

        /* If the HTTP major number is greater than 999 */
        if (UNLIKELY(parser->http_major > 999)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If the HTTP major number is not greater than 999 */

        /* Done with current character */
        break;
      }

      /* If current state is response line after met `HTTP/[0-9][.]` */
      /* first digit of minor HTTP version */
      case s_res_first_http_minor:
        /* If current character is not digit */
        if (UNLIKELY(!IS_NUM(ch))) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit */

        /* Set HTTP minor number */
        parser->http_minor = ch - '0';

        /* Update state */
        UPDATE_STATE(s_res_http_minor);

        /* Done with current character */
        break;

      /* If current state is response line after met `HTTP/[0-9][.][0-9]` */
      /* minor HTTP version or end of request line */
      case s_res_http_minor:
      {
        /* If current character is space */
        if (ch == ' ') {
          /* Update state */
          UPDATE_STATE(s_res_first_status_code);

          /* Done with current character */
          break;
        }
        /* If current character is not space */

        /* If current character is not digit */
        if (UNLIKELY(!IS_NUM(ch))) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit.
         * It means one more digit for the HTTP minor number.
         */

        /* Update HTTP minor number */
        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        /* If the HTTP minor number is greater than 999 */
        if (UNLIKELY(parser->http_minor > 999)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If the HTTP minor number is not greater than 999 */

        /* Done with current character */
        break;
      }

      /* If current state is response line after met `HTTP/[0-9][.][0-9][ ]` */
      case s_res_first_status_code:
      {
        /* If current character is not digit */
        if (!IS_NUM(ch)) {
          /* If current character is space */
          if (ch == ' ') {
            /* Done with current character */
            break;
          }
          /* If current character is not space. */

          /* Set error number */
          SET_ERRNO(HPE_INVALID_STATUS);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit. */

        /* Set status code */
        parser->status_code = ch - '0';

        /* Update state */
        UPDATE_STATE(s_res_status_code);

        /* Done with current character */
        break;
      }

      /* If current state is response line after met
       * `HTTP/[0-9][.][0-9][ ][0-9]`
       */
      case s_res_status_code:
      {
        /* If current character is not digit */
        if (!IS_NUM(ch)) {
          switch (ch) {
            /* If current character is space */
            case ' ':
              /* Update state */
              UPDATE_STATE(s_res_status_start);

              break;
            /* If current character is CR */
            case CR:
              /* Update state */
              UPDATE_STATE(s_res_line_almost_done);

              break;
            /* If current character is LF */
            case LF:
              /* Update state */
              UPDATE_STATE(s_header_field_start);

              break;
            /* If current character is none of above */
            default:
              /* Set error number */
              SET_ERRNO(HPE_INVALID_STATUS);

              /* Goto error handler */
              goto error;
          }

          /* Done with current character */
          break;
        }
        /* If current character is digit.
         * It means one more digit for the status code.
         */

        /* Update status code */
        parser->status_code *= 10;
        parser->status_code += ch - '0';

        /* If the status code is greater than 999 */
        if (UNLIKELY(parser->status_code > 999)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_STATUS);

          /* Goto error handler */
          goto error;
        }
        /* If the status code is not greater than 999 */

        /* Done with current character */
        break;
      }

      /* If current state is response after met status code and a space,
       * e.g. `HTTP/1.1 200 `.
       */
      case s_res_status_start:
      {
        /* If current character is CR */
        if (ch == CR) {
          /* Update state */
          UPDATE_STATE(s_res_line_almost_done);

          /* Done with current character */
          break;
        }
        /* If current character is not CR */

        /* If current character is LF */
        if (ch == LF) {
          /* Update state */
          UPDATE_STATE(s_header_field_start);

          /* Done with current character */
          break;
        }
        /* If current character is not LF */

        /* Mark */
        MARK(status);

        /* Update state */
        UPDATE_STATE(s_res_status);

        /* Reset parser index */
        parser->index = 0;

        /* Done with current character */
        break;
      }

      /* If current state is response line after met the first character of
       * the status message, e.g. `HTTP/1.1 200 O`.
       */
      case s_res_status:
        /* If current character is CR */
        if (ch == CR) {
          /* Update state */
          UPDATE_STATE(s_res_line_almost_done);

          /* Call callback */
          CALLBACK_DATA(status);

          /* Done with current character */
          break;
        }
        /* If current character is not CR */

        /* If current character is LF */
        if (ch == LF) {
          /* Update state */
          UPDATE_STATE(s_header_field_start);

          /* Call callback */
          CALLBACK_DATA(status);

          /* Done with current character */
          break;
        }
        /* If current character is not LF */

        /* Done with current character */
        break;

      /* If current state is response line after met CR */
      case s_res_line_almost_done:
        /* Ensure current character is LF */
        STRICT_CHECK(ch != LF);

        /* Update state */
        UPDATE_STATE(s_header_field_start);

        /* Done with current character */
        break;

      /* If current state is request line start */
      case s_start_req:
      {
        /* If current character is CR or LF */
        if (ch == CR || ch == LF)
          /* Done with current character */
          break;
        /* If current character is not CR or LF */

        /* Reset flags */
        parser->flags = 0;

        /* Reset unread content length */
        parser->content_length = ULLONG_MAX;

        /* If current character is not alphabetic */
        if (UNLIKELY(!IS_ALPHA(ch))) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_METHOD);

          /* Goto error handler */
          goto error;
        }
        /* If current character is alphabetic */

        /* Reset method */
        parser->method = (enum http_method) 0;

        /* Set parser index */
        parser->index = 1;

        /* Map current character to the first possible HTTP method */
        switch (ch) {
          case 'A': parser->method = HTTP_ACL; break;
          case 'B': parser->method = HTTP_BIND; break;
          case 'C': parser->method = HTTP_CONNECT; /* or COPY, CHECKOUT */ break;
          case 'D': parser->method = HTTP_DELETE; break;
          case 'G': parser->method = HTTP_GET; break;
          case 'H': parser->method = HTTP_HEAD; break;
          case 'L': parser->method = HTTP_LOCK; /* or LINK */ break;
          case 'M': parser->method = HTTP_MKCOL; /* or MOVE, MKACTIVITY, MERGE, M-SEARCH, MKCALENDAR */ break;
          case 'N': parser->method = HTTP_NOTIFY; break;
          case 'O': parser->method = HTTP_OPTIONS; break;
          case 'P': parser->method = HTTP_POST;
            /* or PROPFIND|PROPPATCH|PUT|PATCH|PURGE */
            break;
          case 'R': parser->method = HTTP_REPORT; /* or REBIND */ break;
          case 'S': parser->method = HTTP_SUBSCRIBE; /* or SEARCH */ break;
          case 'T': parser->method = HTTP_TRACE; break;
          case 'U': parser->method = HTTP_UNLOCK; /* or UNSUBSCRIBE, UNBIND, UNLINK */ break;
          default:
            /* Set error number */
            SET_ERRNO(HPE_INVALID_METHOD);

            /* Goto error handler */
            goto error;
        }

        /* Update state */
        UPDATE_STATE(s_req_method);

        /* Call callback */
        CALLBACK_NOTIFY(message_begin);

        /* Done with current character */
        break;
      }

      /* If current state is request line after met the first character */
      case s_req_method:
      {
        /* HTTP method name to be matched */
        const char *matcher;

        /* If current character is `\0` */
        if (UNLIKELY(ch == '\0')) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_METHOD);

          /* Goto error handler */
          goto error;
        }
        /* If current character is not `\0` */

        /* Get HTTP method name to be matched */
        matcher = method_strings[parser->method];

        /* If current character is space,
         * and the HTTP method name is matched.
         */
        if (ch == ' ' && matcher[parser->index] == '\0') {
          /* Update state */
          UPDATE_STATE(s_req_spaces_before_url);
        /* If current character is matched */
        } else if (ch == matcher[parser->index]) {
          /* Done with current character */
          ; /* nada */
        /* If current character is not matched.
         * If current character is alphabetic.
         * This means current character still has the chance of matching an
         * alternative method name with the same matched prefix.
         */
        } else if (IS_ALPHA(ch)) {

          /* Combine the method value, the parser index and current character
           * into a int, to be used as the lookup key of the alternative
           * methods table implemented in the switch block below.
           *
           * If the key is found in the alternative methods table, the
           * alternative method is used for the next matching.
           *
           * `<< 16` means put the method value in the third byte of the int.
           * `<< 8` means put the parser index in the second byte of the int.
           * Current character is put in the first byte of the int.
           */
          switch (parser->method << 16 | parser->index << 8 | ch) {
#define XX(meth, pos, ch, new_meth) \
            case (HTTP_##meth << 16 | pos << 8 | ch): \
              parser->method = HTTP_##new_meth; break;

            XX(POST,      1, 'U', PUT)
            XX(POST,      1, 'A', PATCH)
            XX(CONNECT,   1, 'H', CHECKOUT)
            XX(CONNECT,   2, 'P', COPY)
            XX(MKCOL,     1, 'O', MOVE)
            XX(MKCOL,     1, 'E', MERGE)
            XX(MKCOL,     2, 'A', MKACTIVITY)
            XX(MKCOL,     3, 'A', MKCALENDAR)
            XX(SUBSCRIBE, 1, 'E', SEARCH)
            XX(REPORT,    2, 'B', REBIND)
            XX(POST,      1, 'R', PROPFIND)
            XX(PROPFIND,  4, 'P', PROPPATCH)
            XX(PUT,       2, 'R', PURGE)
            XX(LOCK,      1, 'I', LINK)
            XX(UNLOCK,    2, 'S', UNSUBSCRIBE)
            XX(UNLOCK,    2, 'B', UNBIND)
            XX(UNLOCK,    3, 'I', UNLINK)
#undef XX

            /* If an alternative method is not found */
            default:
              /* Set error number */
              SET_ERRNO(HPE_INVALID_METHOD);

              /* Goto error handler */
              goto error;
          }
        /* If current character is not matched.
         * If current character is not alphabetic.
         * If current character is `-`,
         * and the parser index is 1,
         * and the method is HTTP_MKCOL.
         */
        } else if (ch == '-' &&
                   parser->index == 1 &&
                   parser->method == HTTP_MKCOL) {
          /* Set the method be HTTP_MSEARCH */
          parser->method = HTTP_MSEARCH;
        /* If current character is none of above */
        } else {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_METHOD);

          /* Goto error handler */
          goto error;
        }

        /* Increment the parser index */
        ++parser->index;

        /* Done with current character */
        break;
      }

      /* If current state is request line after met HTTP method */
      case s_req_spaces_before_url:
      {
        /* If current character is space.
         * Done with current character.
         */
        if (ch == ' ') break;
        /* If current character is not space */

        /* Mark */
        MARK(url);

        /* If the HTTP method is HTTP_CONNECT */
        if (parser->method == HTTP_CONNECT) {
          /* Update state */
          UPDATE_STATE(s_req_server_start);
        }

        /* Decide next state.
         * Update state.
         */
        UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));

        /* If current state is dead state */
        if (UNLIKELY(CURRENT_STATE() == s_dead)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_URL);

          /* Goto error handler */
          goto error;
        }
        /* If current state is not dead state */

        /* Done with current character */
        break;
      }

      /* If current state is one of these */
      case s_req_schema:
      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      {
        switch (ch) {
          /* If current character is space, CR, or LF */
          /* No whitespace allowed here */
          case ' ':
          case CR:
          case LF:
            /* Set error number */
            SET_ERRNO(HPE_INVALID_URL);

            /* Goto error handler */
            goto error;
          /* If current character is not space, CR, or LF */
          default:
            /* Decide next state.
             * Update state.
             */
            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));

            /* If current state is dead state */
            if (UNLIKELY(CURRENT_STATE() == s_dead)) {
              /* Set error number */
              SET_ERRNO(HPE_INVALID_URL);

              /* Goto error handler */
              goto error;
            }
            /* If current state is not dead state */
        }

        /* Done with current character */
        break;
      }

      /* If current state is one of these */
      case s_req_server:
      case s_req_server_with_at:
      case s_req_path:
      case s_req_query_string_start:
      case s_req_query_string:
      case s_req_fragment_start:
      case s_req_fragment:
      {
        switch (ch) {
          /* If current character is space.
           * It means end of request path, and what follows might be HTTP
           * protocol version, e.g. `GET / ` followed by `GET / HTTP/1.1`.
           */
          case ' ':
            /* Update state */
            UPDATE_STATE(s_req_http_start);

            /* Call callback */
            CALLBACK_DATA(url);

            /* Done with current character */
            break;
          /* If current character is CR or LF.
           * It means the HTTP protocol version is absent,
           * e.g. `GET /[\r][\n]` instead of `GET / HTTP/1.1[\r][\n]`.
           */
          case CR:
          case LF:
            /* Use default HTTP major number */
            parser->http_major = 0;

            /* Use default HTTP minor number */
            parser->http_minor = 9;

            /* Update state */
            UPDATE_STATE((ch == CR) ?
              s_req_line_almost_done :
              s_header_field_start);

            /* Call callback */
            CALLBACK_DATA(url);

            /* Done with current character */
            break;
          /* If current character is none of above */
          default:
            /* Decide next state.
             * Update state.
             */
            UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));

            /* If current state is dead state */
            if (UNLIKELY(CURRENT_STATE() == s_dead)) {
              /* Set error number */
              SET_ERRNO(HPE_INVALID_URL);

              /* Goto error handler */
              goto error;
            }
            /* If current state is not dead state */
        }

        /* Done with current character */
        break;
      }

      /* If current state is request line after met request path, e.g. `GET / `
       */
      case s_req_http_start:
        switch (ch) {
          /* If current character is `H`.
           * It might be HTTP protocol version, e.g. `HTTP/1.1` of
           * `GET / HTTP/1.1`
           */
          case 'H':
            /* Update state */
            UPDATE_STATE(s_req_http_H);

            /* Done with current character */
            break;
          /* If current character is space, e.g. `GET /  ` */
          case ' ':
            /* Done with current character */
            break;
          /* If current character is none of above */
          default:
            /* Set error number */
            SET_ERRNO(HPE_INVALID_CONSTANT);

            /* Goto error handler */
            goto error;
        }
        /* Done with current character */
        break;

      /* If current state is request line protocol version after met 'H',
       * e.g. `GET / H`.
       */
      case s_req_http_H:
        /* Ensure current character is `T` .
         * Ensure current characters are `HT`.
         */
        STRICT_CHECK(ch != 'T');

        /* Update state */
        UPDATE_STATE(s_req_http_HT);

        /* Done with current character */
        break;

      /* If current state is request line protocol version after met 'HT',
       * e.g. `GET / HT`.
       */
      case s_req_http_HT:
        /* Ensure current character is `T` .
         * Ensure current characters are `HTT`.
         */
        STRICT_CHECK(ch != 'T');

        /* Update state */
        UPDATE_STATE(s_req_http_HTT);

        /* Done with current character */
        break;

      /* If current state is request line protocol version after met 'HTT',
       * e.g. `GET / HTT`.
       */
      case s_req_http_HTT:
        /* Ensure current character is `P` .
         * Ensure current characters are `HTTP`.
         */
        STRICT_CHECK(ch != 'P');

        /* Update state */
        UPDATE_STATE(s_req_http_HTTP);

        /* Done with current character */
        break;

      /* If current state is request line protocol version after met 'HTTP',
       * e.g. `GET / HTTP`.
       */
      case s_req_http_HTTP:
        /* Ensure current character is `/` .
         * Ensure current characters are `HTTP/`.
         */
        STRICT_CHECK(ch != '/');

        /* Update state */
        UPDATE_STATE(s_req_first_http_major);

        /* Done with current character */
        break;

      /* If current state is request line protocol version after met 'HTTP/',
       * e.g. `GET / HTTP/`.
       */
      /* first digit of major HTTP version */
      case s_req_first_http_major:
        /* If current character is not digit */
        if (UNLIKELY(ch < '1' || ch > '9')) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit */

        /* Set HTTP major number */
        parser->http_major = ch - '0';

        /* Update state */
        UPDATE_STATE(s_req_http_major);

        /* Done with current character */
        break;

      /* If current state is request line protocol version after met
       * `HTTP/[0-9]`, e.g. `GET / HTTP/1`.
       */
      /* major HTTP version or dot */
      case s_req_http_major:
      {
        /* If current character is `.` */
        if (ch == '.') {
          /* Update state */
          UPDATE_STATE(s_req_first_http_minor);

          /* Done with current character */
          break;
        }
        /* If current character is not `.` */

        /* If current character is not digit */
        if (UNLIKELY(!IS_NUM(ch))) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit.
         * It means one more digit for the HTTP major number.
         */

        /* Update HTTP major number */
        parser->http_major *= 10;
        parser->http_major += ch - '0';

        /* If the HTTP major number is greater than 999 */
        if (UNLIKELY(parser->http_major > 999)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If the HTTP major number is not greater than 999 */

        /* Done with current character */
        break;
      }

      /* If current state is request line protocol version after met
       * `HTTP/[0-9][.]`, e.g. `GET / HTTP/1.`.
       */
      /* first digit of minor HTTP version */
      case s_req_first_http_minor:
        /* If current character is not digit */
        if (UNLIKELY(!IS_NUM(ch))) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit */

        /* Set HTTP minor number */
        parser->http_minor = ch - '0';

        /* Update state */
        UPDATE_STATE(s_req_http_minor);

        /* Done with current character */
        break;

      /* If current state is request line protocol version after met
       * `HTTP/[0-9][.][0-9]`, e.g. `GET / HTTP/1.1`.
       */
      /* minor HTTP version or end of request line */
      case s_req_http_minor:
      {
        /* If current character is CR */
        if (ch == CR) {
        /* Update state */
          UPDATE_STATE(s_req_line_almost_done);

          /* Done with current character */
          break;
        }
        /* If current character is not CR */

        /* If current character is LF */
        if (ch == LF) {
        /* Update state */
          UPDATE_STATE(s_header_field_start);

          /* Done with current character */
          break;
        }
        /* If current character is not LF */

        /* XXX allow spaces after digit? */

        /* If current character is not digit */
        if (UNLIKELY(!IS_NUM(ch))) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If current character is digit.
         * It means one more digit for the HTTP minor number.
         */

        /* Update HTTP minor number */
        parser->http_minor *= 10;
        parser->http_minor += ch - '0';

        /* If the HTTP major number is greater than 999 */
        if (UNLIKELY(parser->http_minor > 999)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_VERSION);

          /* Goto error handler */
          goto error;
        }
        /* If the HTTP major number is not greater than 999 */

        /* Done with current character */
        break;
      }

      /* If current state is request line after met CR, e.g.
       * `GET / HTTP/1.1[\r]`
       */
      /* end of request line */
      case s_req_line_almost_done:
      {
        /* If current character is not LF */
        if (UNLIKELY(ch != LF)) {
          /* Set error number */
          SET_ERRNO(HPE_LF_EXPECTED);

          /* Goto error handler */
          goto error;
        }
        /* If current character is LF */

        /* Update state */
        UPDATE_STATE(s_header_field_start);

        /* Done with current character */
        break;
      }

      /* If current state is header field start */
      case s_header_field_start:
      {
        /* If current character is CR.
         * It means end of headers section.
         */
        if (ch == CR) {
          /* Update state */
          UPDATE_STATE(s_headers_almost_done);

          /* Done with current character */
          break;
        }
        /* If current character is not CR */

        /* If current character is LF.
         * It means end of headers section.
         */
        if (ch == LF) {
          /* Update state */
          /* they might be just sending \n instead of \r\n so this would be
           * the second \n to denote the end of headers*/
          UPDATE_STATE(s_headers_almost_done);

          /* Re-parse with new state */
          REEXECUTE();
        }
        /* If current character is not LF */

        /* Map current character to token */
        c = TOKEN(ch);

        /* If current character is not valid token */
        if (UNLIKELY(!c)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_HEADER_TOKEN);

          /* Goto error handler */
          goto error;
        }
        /* If current character is valid token */

        /* Mark */
        MARK(header_field);

        /* Reset parser index */
        parser->index = 0;

        /* Update state */
        UPDATE_STATE(s_header_field);

        switch (c) {
          /* If the token is `c`.
           * It might be header `Connection` or `Content-Length`.
           */
          case 'c':
            /* Set header state */
            parser->header_state = h_C;

            /* Done with current character */
            break;

          /* If the token is `p`.
           * It might be header `Proxy-Connection`.
           */
          case 'p':
            /* Set header state */
            parser->header_state = h_matching_proxy_connection;

            /* Done with current character */
            break;

          /* If the token is `t`.
           * It might be header `Transfer-Encoding`.
           */
          case 't':
            /* Set header state */
            parser->header_state = h_matching_transfer_encoding;

            /* Done with current character */
            break;

          /* If the token is `u`.
           * It might be header `Upgrade`.
           */
          case 'u':
            /* Set header state */
            parser->header_state = h_matching_upgrade;

            /* Done with current character */
            break;

          /* If the token is none of above.
           * It is a general header (as far as this parser is concerned).
           */
          default:
            /* Set header state */
            parser->header_state = h_general;

            /* Done with current character */
            break;
        }

        /* Done with current character */
        break;
      }

      /* If current state is header name start */
      case s_header_field:
      {
        /* Store start character pointer */
        const char* start = p;

        /* For each character */
        for (; p != data + len; p++) {
          /* Get current character */
          ch = *p;

          /* Map current character to token */
          c = TOKEN(ch);

          /* If current character is not valid token.
           * It might be the `:` character after header name is met.
           */
          if (!c)
            /* Break the loop */
            break;
          /* If current character is valid token */

          switch (parser->header_state) {
            /* If the header state is general */
            case h_general:
              /* Done with current character */
              break;

            /* If the header state is after met `c` */
            case h_C:
              /* Increment parser index */
              parser->index++;

              /* Update header state */
              parser->header_state = (c == 'o' ? h_CO : h_general);

              /* Done with current character */
              break;

            /* If the header state is after met `co` */
            case h_CO:
              /* Increment parser index */
              parser->index++;

              /* Update header state */
              parser->header_state = (c == 'n' ? h_CON : h_general);

              /* Done with current character */
              break;

            /* If the header state is after met `con` */
            case h_CON:
              /* Increment parser index */
              parser->index++;

              switch (c) {
                /* If the token is `n`.
                 * It might be header `Connection`.
                 */
                case 'n':
                  /* Update header state */
                  parser->header_state = h_matching_connection;

                  /* Done with current character */
                  break;
                /* If the token is `t`.
                 * It might be header `Content-Length`.
                 */
                case 't':
                  /* Update header state */
                  parser->header_state = h_matching_content_length;

                  /* Done with current character */
                  break;
                /* If the token is none of above.
                 * It is a general header.
                 */
                default:
                  /* Update header state */
                  parser->header_state = h_general;

                  /* Done with current character */
                  break;
              }

              /* Done with current character */
              break;

            /* connection */

            /* If the header state is matching `Connection` */
            case h_matching_connection:
              /* Increment parser index */
              parser->index++;

              /* If the header name is longer than `Connection`,
               * or current character is not matched with `Connection`.
               * It is a general header.
               */
              if (parser->index > sizeof(CONNECTION)-1
                  || c != CONNECTION[parser->index]) {
                /* Update header state */
                parser->header_state = h_general;
              /* If the last character of `Connection` is matched */
              } else if (parser->index == sizeof(CONNECTION)-2) {
                /* Update header state */
                parser->header_state = h_connection;
              }

              /* Done with current character */
              break;

            /* proxy-connection */

            /* If the header state is matching `Proxy-Connection` */
            case h_matching_proxy_connection:
              /* Increment parser index */
              parser->index++;

              /* If the header name is longer than `Proxy-Connection`,
               * or current character is not matched with `Proxy-Connection`.
               * It is a general header.
               */
              if (parser->index > sizeof(PROXY_CONNECTION)-1
                  || c != PROXY_CONNECTION[parser->index]) {
                /* Update header state */
                parser->header_state = h_general;
              /* If the last character of `Proxy-Connection` is matched */
              } else if (parser->index == sizeof(PROXY_CONNECTION)-2) {
                /* Update header state */
                parser->header_state = h_connection;
              }

              /* Done with current character */
              break;

            /* content-length */

            /* If the header state is matching `Content-Length` */
            case h_matching_content_length:
              /* Increment parser index */
              parser->index++;

              /* If the header name is longer than `Content-Length`,
               * or current character is not matched with `Content-Length`.
               * It is a general header.
               */
              if (parser->index > sizeof(CONTENT_LENGTH)-1
                  || c != CONTENT_LENGTH[parser->index]) {
                /* Update header state */
                parser->header_state = h_general;
              /* If the last character of `Content-Length` is matched */
              } else if (parser->index == sizeof(CONTENT_LENGTH)-2) {
                /* Update header state */
                parser->header_state = h_content_length;
              }

              /* Done with current character */
              break;

            /* transfer-encoding */

            /* If the header state is matching `Transfer-Encoding` */
            case h_matching_transfer_encoding:
              /* Increment parser index */
              parser->index++;

              /* If the header name is longer than `Transfer-Encoding`,
               * or current character is not matched with `Transfer-Encoding`.
               * It is a general header.
               */
              if (parser->index > sizeof(TRANSFER_ENCODING)-1
                  || c != TRANSFER_ENCODING[parser->index]) {
                /* Update header state */
                parser->header_state = h_general;
              /* If the last character of `Transfer-Encoding` is matched */
              } else if (parser->index == sizeof(TRANSFER_ENCODING)-2) {
                /* Update header state */
                parser->header_state = h_transfer_encoding;
              }

              /* Done with current character */
              break;

            /* upgrade */

            /* If the header state is matching `Upgrade` */
            case h_matching_upgrade:
              /* Increment parser index */
              parser->index++;

              /* If the header name is longer than `Upgrade`,
               * or current character is not matched with `Upgrade`.
               * It is a general header.
               */
              if (parser->index > sizeof(UPGRADE)-1
                  || c != UPGRADE[parser->index]) {
                /* Update header state */
                parser->header_state = h_general;
              /* If the last character of `Upgrade` is matched */
              } else if (parser->index == sizeof(UPGRADE)-2) {
                /* Update header state */
                parser->header_state = h_upgrade;
              }

              /* Done with current character */
              break;

            /* If the header state is have matched one of these prefixes,
             * before a `:` or space to end the matched header name. */
            case h_connection:
            case h_content_length:
            case h_transfer_encoding:
            case h_upgrade:
              /* If current character is not space.
               * It is a general header.
               */
              if (ch != ' ') parser->header_state = h_general;
              /* If current character is space.
               * It means a special header name has been matched.
               */

              /* Done with current character */
              break;

            /* If the header state is none of above */
            default:
              /* Assert error */
              assert(0 && "Unknown header_state");

              /* Done with current character */
              break;
          }
        }

        /* Increase already-read counter `parser->nread`.
         * Ensure the counter is within limit.
         */
        COUNT_HEADER_SIZE(p - start);

        /* If current character pointer reached data end */
        if (p == data + len) {
          /* Decrement current character pointer, so that the last increment by
           * the outer for loop will not make the pointer overrun.
           */
          --p;

          /* Done with current character */
          break;
        }
        /* If current character pointer not reached data end */

        /* If current character is `:` */
        if (ch == ':') {
          /* Update state */
          UPDATE_STATE(s_header_value_discard_ws);

          /* Call callback */
          CALLBACK_DATA(header_field);

          /* Done with current character */
          break;
        }
        /* If current character is not `:` */

        /* Set error number */
        SET_ERRNO(HPE_INVALID_HEADER_TOKEN);

        /* Goto error handler */
        goto error;
      }

      /* If current state is discard whitespace before header value */
      case s_header_value_discard_ws:
        /* If current character is space or tab.
         * Done with current character.
         */
        if (ch == ' ' || ch == '\t') break;
        /* If current character is not space or tab */

        /* If current character is CR.
         * It means there will be a CRLF before start of the header value.
         */
        if (ch == CR) {
          /* Update state */
          UPDATE_STATE(s_header_value_discard_ws_almost_done);

          /* Done with current character */
          break;
        }
        /* If current character is not CR */

        /* If current character is LF.
         * It means there will be a CRLF before start of the header value.
         */
        if (ch == LF) {
          /* Update state */
          UPDATE_STATE(s_header_value_discard_lws);

          /* Done with current character */
          break;
        }
        /* If current character is not LF */

        /* FALLTHROUGH */

      /* If current state is header value start */
      case s_header_value_start:
      {
        /* Mark */
        MARK(header_value);

        /* Update state */
        UPDATE_STATE(s_header_value);

        /* Reset parser index */
        parser->index = 0;

        /* Get lowercase current character */
        c = LOWER(ch);

        switch (parser->header_state) {
          /* If the header state is `Upgrade` */
          case h_upgrade:
            /* Add flag */
            parser->flags |= F_UPGRADE;

            /* Update header state */
            parser->header_state = h_general;

            /* Done with current character */
            break;

          /* If the header state is `Transfer-Encoding` */
          case h_transfer_encoding:
            /* If current character is `c`.
             * It might be `Transfer-Encoding: chunked`.
             */
            /* looking for 'Transfer-Encoding: chunked' */
            if ('c' == c) {
              /* Update header state */
              parser->header_state = h_matching_transfer_encoding_chunked;
            /* If current character is not `c`.
             * It is a general header.
             */
            } else {
              /* Update header state */
              parser->header_state = h_general;
            }

            /* Done with current character */
            break;

          /* If the header state is `Content-Length` */
          case h_content_length:
            /* If current character is not digit */
            if (UNLIKELY(!IS_NUM(ch))) {
              /* Set error number */
              SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);

              /* Goto error handler */
              goto error;
            }
            /* If current character is digit */

            /* If have flag `F_CONTENTLENGTH` */
            if (parser->flags & F_CONTENTLENGTH) {
              /* Set error number */
              SET_ERRNO(HPE_UNEXPECTED_CONTENT_LENGTH);

              /* Goto error handler */
              goto error;
            }
            /* If not have flag `F_CONTENTLENGTH` */

            /* Add flag */
            parser->flags |= F_CONTENTLENGTH;

            /* Set unread content length */
            parser->content_length = ch - '0';

            /* Done with current character */
            break;

          /* If the header state is `Connection` */
          case h_connection:
            /* If current character is `k`.
             * It might be `Connection: keep-alive`.
             */
            /* looking for 'Connection: keep-alive' */
            if (c == 'k') {
              /* Update header state */
              parser->header_state = h_matching_connection_keep_alive;
            /* If current character is `c`.
             * It might be `Connection: close`.
             */
            /* looking for 'Connection: close' */
            } else if (c == 'c') {
              /* Update header state */
              parser->header_state = h_matching_connection_close;
            /* If current character is `u`.
             * It might be `Connection: upgrade`.
             */
            } else if (c == 'u') {
              /* Update header state */
              parser->header_state = h_matching_connection_upgrade;
            /* If current character is none of above.
             * It is a general header.
             */
            } else {
              /* Update header state */
              parser->header_state = h_matching_connection_token;
            }

            /* Done with current character */
            break;

          /* If the header state is `Connection` after met multi-value
           * separator `,`, e.g. `Connection: keep-alive,`.
           */
          /* Multi-value `Connection` header */
          case h_matching_connection_token_start:
            /* Done with current character */
            break;

          /* If the header state is none of above.
           * It is a general header.
           */
          default:
            /* Update header state */
            parser->header_state = h_general;

            /* Done with current character */
            break;
        }

        /* Done with current character */
        break;
      }

      /* If current state is header value */
      case s_header_value:
      {
        /* Store start character pointer */
        const char* start = p;

        /* Store original header state */
        enum header_states h_state = (enum header_states) parser->header_state;

        /* For each character */
        for (; p != data + len; p++) {
          /* Get current character */
          ch = *p;

          /* If current character is CR.
           * It means end of header value.
           */
          if (ch == CR) {
            /* Update state */
            UPDATE_STATE(s_header_almost_done);

            /* Restore original header state */
            parser->header_state = h_state;

            /* Call callback */
            CALLBACK_DATA(header_value);

            /* Done with current character */
            break;
          }
          /* If current character is not CR */

          /* If current character is LF.
           * It means end of header value.
           */
          if (ch == LF) {
            /* Update state */
            UPDATE_STATE(s_header_almost_done);

            /* Increase already-read counter `parser->nread`.
             * Ensure the counter is within limit.
             */
            COUNT_HEADER_SIZE(p - start);

            /* Restore original header state */
            parser->header_state = h_state;

            /* Call callback */
            CALLBACK_DATA_NOADVANCE(header_value);

            /* Re-parse with new state */
            REEXECUTE();
          }
          /* If current character is not LF */

          /* If not lenient on header characters,
           * and current character is not valid header character.
           */
          if (!lenient && !IS_HEADER_CHAR(ch)) {
            /* Set error number */
            SET_ERRNO(HPE_INVALID_HEADER_TOKEN);

            /* Goto error handler */
            goto error;
          }
          /* If lenient on header characters,
           * or current character is valid header character.
           */

          /* Get lowercase current character */
          c = LOWER(ch);

          switch (h_state) {
            /* If the header state is after met a general header name */
            case h_general:
            {
              /* Pointer of the next CR */
              const char* p_cr;

              /* Pointer of the next LF */
              const char* p_lf;

              /* Get remaining data length */
              size_t limit = data + len - p;

              /* Get length limit for the `memchr` call below */
              limit = MIN(limit, HTTP_MAX_HEADER_SIZE);

              /* Find the next CR */
              p_cr = (const char*) memchr(p, CR, limit);

              /* Find the next LF */
              p_lf = (const char*) memchr(p, LF, limit);

              /* If the next CR is found */
              if (p_cr != NULL) {
                /* If the next LF is found,
                 * and the next LF is before the next CR.
                 */
                if (p_lf != NULL && p_cr >= p_lf)
                  /* Use remaining data before the next LF as header value */
                  p = p_lf;
                /* If the next LF is not found,
                 * or the next LF is after the next CR.
                 */
                else
                  /* Use remaining data before the next CR as header value */
                  p = p_cr;
              /* If the next CR is not found.
               * If the next LF is found.
               */
              } else if (UNLIKELY(p_lf != NULL)) {
                /* Use remaining data before the next LF as header value */
                p = p_lf;
              /* If the next CR is not found.
               * If the next LF is not found.
               */
              } else {
                /* Use all remaining data as header value */
                p = data + len;
              }

              /* Decrement current character pointer, so that the last
               * increment by the outer for loop will not make the pointer
               * overrun.
               */
              --p;

              /* Done with current character */
              break;
            }

            /* If the header state is after met `Connection:` or
             * `Transfer-Encoding:`
             */
            case h_connection:
            case h_transfer_encoding:
              /* Assert error */
              assert(0 && "Shouldn't get here.");

              /* Done with current character */
              break;

            /* If the header state is after met `Content-Length:` */
            case h_content_length:
            {
              /* Unread content length */
              uint64_t t;

              /* If current character is space.
               * Done with current character.
               */
              if (ch == ' ') break;
              /* If current character is not space */

              /* If current character is not digit */
              if (UNLIKELY(!IS_NUM(ch))) {
                /* Set error number */
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);

                /* Restore original header state */
                parser->header_state = h_state;

                /* Goto error handler */
                goto error;
              }
              /* If current character is digit */

              /* Get unread content length */
              t = parser->content_length;

              /* Update unread content length */
              t *= 10;
              t += ch - '0';

              /* If unread content length is too large */
              /* Overflow? Test against a conservative limit for simplicity. */
              if (UNLIKELY((ULLONG_MAX - 10) / 10 < parser->content_length)) {
                /* Set error number */
                SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);

                /* Restore original header state */
                parser->header_state = h_state;

                /* Goto error handler */
                goto error;
              }
              /* If unread content length is not too large */

              /* Set unread content length */
              parser->content_length = t;

              /* Done with current character */
              break;
            }

            /* If the header state is matching `Transfer-Encoding: chunked`
             * after met `Transfer-Encoding: `.
             */
            /* Transfer-Encoding: chunked */
            case h_matching_transfer_encoding_chunked:
              /* Increment parser index */
              parser->index++;

              /* If the header value is longer than `chunked`,
               * or current character is not matched with `chunked`.
               * It is a general header value.
               */
              if (parser->index > sizeof(CHUNKED)-1
                  || c != CHUNKED[parser->index]) {
                /* Update header state */
                h_state = h_general;
              /* If the last character of `chunked` is matched */
              } else if (parser->index == sizeof(CHUNKED)-2) {
                /* Update header state */
                h_state = h_transfer_encoding_chunked;
              }

              /* Done with current character */
              break;

            /* If the header state is `Connection` after met multi-value
             * separator `,`, e.g. `Connection: keep-alive,`.
             */
            case h_matching_connection_token_start:
              /* If current character is `k`.
               * It might be `Connection: some-value,keep-alive`.
               */
              /* looking for 'Connection: keep-alive' */
              if (c == 'k') {
                /* Update header state */
                h_state = h_matching_connection_keep_alive;
              /* If current character is `c`.
               * It might be `Connection: some-value,close`.
               */
              /* looking for 'Connection: close' */
              } else if (c == 'c') {
                /* Update header state */
                h_state = h_matching_connection_close;
              /* If current character is `u`.
               * It might be `Connection: some-value,upgrade`.
               */
              } else if (c == 'u') {
                /* Update header state */
                h_state = h_matching_connection_upgrade;
              /* If current character is valid token.
               * It is a general header value.
               */
              } else if (STRICT_TOKEN(c)) {
                /* Update header state */
                h_state = h_matching_connection_token;
              /* If current character is space or tab */
              } else if (c == ' ' || c == '\t') {
                /* Skip lws */
              /* If current character is none of above.
               * It is a general header.
               */
              } else {
                /* Update header state */
                h_state = h_general;
              }

              /* Done with current character */
              break;

            /* If the header state is matching `Connection: keep-alive` after
             * met `Connection: `.
             */
            /* looking for 'Connection: keep-alive' */
            case h_matching_connection_keep_alive:
              /* Increment parser index */
              parser->index++;

              /* If the header value is longer than `keep-alive`,
               * or current character is not matched with `keep-alive`.
               * It is a general header value.
               */
              if (parser->index > sizeof(KEEP_ALIVE)-1
                  || c != KEEP_ALIVE[parser->index]) {
                /* Update header state */
                h_state = h_matching_connection_token;
              /* If the last character of `keep-alive` is matched */
              } else if (parser->index == sizeof(KEEP_ALIVE)-2) {
                /* Update header state */
                h_state = h_connection_keep_alive;
              }

              /* Done with current character */
              break;

            /* If the header state is matching `Connection: close` after met
             * `Connection: `.
             */
            /* looking for 'Connection: close' */
            case h_matching_connection_close:
              /* Increment parser index */
              parser->index++;

              /* If the header value is longer than `close`,
               * or current character is not matched with `close`.
               * It is a general header value.
               */
              if (parser->index > sizeof(CLOSE)-1 || c != CLOSE[parser->index]) {
                /* Update header state */
                h_state = h_matching_connection_token;
              /* If the last character of `close` is matched */
              } else if (parser->index == sizeof(CLOSE)-2) {
                /* Update header state */
                h_state = h_connection_close;
              }

              /* Done with current character */
              break;

            /* If the header state is matching `Connection: upgrade` after met
             * `Connection: `.
             */
            /* looking for 'Connection: upgrade' */
            case h_matching_connection_upgrade:
              /* Increment parser index */
              parser->index++;

              /* If the header value is longer than `upgrade`,
               * or current character is not matched with `upgrade`.
               * It is a general header value.
               */
              if (parser->index > sizeof(UPGRADE) - 1 ||
                  c != UPGRADE[parser->index]) {
                /* Update header state */
                h_state = h_matching_connection_token;
              /* If the last character of `upgrade` is matched */
              } else if (parser->index == sizeof(UPGRADE)-2) {
                /* Update header state */
                h_state = h_connection_upgrade;
              }

              /* Done with current character */
              break;

            /* If the header state is matching `Connection: some-value` after
             * met `Connection: `.
             */
            case h_matching_connection_token:
              /* If current character is `,`.
               * It means multi-value separator.
               */
              if (ch == ',') {
                /* Update header state */
                h_state = h_matching_connection_token_start;

                /* Reset parser index */
                parser->index = 0;
              }

              /* Done with current character */
              break;

            /* If the header state is after met `Transfer-Encoding: chunked` */
            case h_transfer_encoding_chunked:
              /* If current character is not space.
               * It is a general header value.
               * Update header state.
               */
              if (ch != ' ') h_state = h_general;

              /* Done with current character */
              break;

            /* If the header state is after met `Connection: keep-alive`,
             * `Connection: close`, or `Connection: upgrade`.
             */
            case h_connection_keep_alive:
            case h_connection_close:
            case h_connection_upgrade:
              /* If current character is `,` */
              if (ch == ',') {
                /* If the header state is after met `Connection: keep-alive` */
                if (h_state == h_connection_keep_alive) {
                  /* Add flag */
                  parser->flags |= F_CONNECTION_KEEP_ALIVE;
                /* If the header state is after met `Connection: close` */
                } else if (h_state == h_connection_close) {
                  /* Add flag */
                  parser->flags |= F_CONNECTION_CLOSE;
                /* If the header state is after met `Connection: upgrade` */
                } else if (h_state == h_connection_upgrade) {
                  /* Add flag */
                  parser->flags |= F_CONNECTION_UPGRADE;
                }

                /* Update header state */
                h_state = h_matching_connection_token_start;

                /* Reset parser index */
                parser->index = 0;
              /* If current character is not `,`.
               * If current character is not space.
               * It is a general header value.
               */
              } else if (ch != ' ') {
                /* Update header state */
                h_state = h_matching_connection_token;
              }

              /* Done with current character */
              break;

            /* If the header state is none of above.
             * It is a general header value.
             */
            default:
              /* Update state */
              UPDATE_STATE(s_header_value);

              /* Update header state */
              h_state = h_general;

              /* Done with current character */
              break;
          }
        }

        /* Restore original header state */
        parser->header_state = h_state;

        /* Increase already-read counter `parser->nread`.
         * Ensure the counter is within limit.
         */
        COUNT_HEADER_SIZE(p - start);

        /* If current character pointer reached data end */
        if (p == data + len)
          /* Decrement current character pointer, so that the last increment by
           * the outer for loop will not make the pointer overrun.
           */
          --p;

        /* Done with current character */
        break;
      }

      /* If current state is header value after met CR */
      case s_header_almost_done:
      {
        /* If current character is not LF */
        if (UNLIKELY(ch != LF)) {
          /* Set error number */
          SET_ERRNO(HPE_LF_EXPECTED);

          /* Goto error handler */
          goto error;
        }
        /* If current character is LF */

        /* Update state */
        UPDATE_STATE(s_header_value_lws);

        /* Done with current character */
        break;
      }

      /* If current state is header value after met CRLF */
      case s_header_value_lws:
      {
        /* If current character is space or tab.
         * It means continuation of the header value after CRLF.
         */
        if (ch == ' ' || ch == '\t') {
          /* Update state */
          UPDATE_STATE(s_header_value_start);

          /* Re-parse with new state */
          REEXECUTE();
        }
        /* If current character is not space or tab.
         * It means end of header value.
         */

        /* finished the header */
        switch (parser->header_state) {
          /* If the header state is after met `Connection: keep-alive` */
          case h_connection_keep_alive:
            /* Add flag */
            parser->flags |= F_CONNECTION_KEEP_ALIVE;

            break;
          /* If the header state is after met `Connection: close` */
          case h_connection_close:
            /* Add flag */
            parser->flags |= F_CONNECTION_CLOSE;

            break;
          /* If the header state is after met `Transfer-Encoding: chunked` */
          case h_transfer_encoding_chunked:
            /* Add flag */
            parser->flags |= F_CHUNKED;

            break;
          /* If the header state is after met `Connection: upgrade` */
          case h_connection_upgrade:
            /* Add flag */
            parser->flags |= F_CONNECTION_UPGRADE;

            break;
          /* If the header state is none of above */
          default:
            break;
        }

        /* Update state */
        UPDATE_STATE(s_header_field_start);

        /* Re-parse with new state */
        REEXECUTE();
      }

      /* If current state is discard whitespace before header value, and met
       * CR.
       */
      case s_header_value_discard_ws_almost_done:
      {
        /* Ensure current character is LF */
        STRICT_CHECK(ch != LF);

        /* Update state */
        UPDATE_STATE(s_header_value_discard_lws);

        /* Done with current character */
        break;
      }

      /* If current state is discard whitespace before header value, and met
       * CRLF.
       */
      case s_header_value_discard_lws:
      {
        /* If current character is space or tab.
         * It means the header value continues after the CRLF met.
         */
        if (ch == ' ' || ch == '\t') {
          /* Update state */
          UPDATE_STATE(s_header_value_discard_ws);

          /* Done with current character */
          break;
        /* If current character is not space or tab.
         * It means the header value is empty and the next header starts.
         */
        } else {
          switch (parser->header_state) {
            /* If the header state is `Connection: keep-alive` */
            case h_connection_keep_alive:
              /* Add flag */
              parser->flags |= F_CONNECTION_KEEP_ALIVE;
              break;
            /* If the header state is `Connection: close` */
            case h_connection_close:
              /* Add flag */
              parser->flags |= F_CONNECTION_CLOSE;
              break;
            /* If the header state is `Connection: upgrade` */
            case h_connection_upgrade:
              /* Add flag */
              parser->flags |= F_CONNECTION_UPGRADE;
              break;
            /* If the header state is `Transfer-Encoding: chunked` */
            case h_transfer_encoding_chunked:
              /* Add flag */
              parser->flags |= F_CHUNKED;
              break;
            default:
              break;
          }

          /* Mark */
          /* header value was empty */
          MARK(header_value);

          /* Update state */
          UPDATE_STATE(s_header_field_start);

          /* Call callback */
          CALLBACK_DATA_NOADVANCE(header_value);

          /* Re-parse with new state */
          REEXECUTE();
        }
      }

      /* If current state is headers almost done, after met CR or LF */
      case s_headers_almost_done:
      {
        /* Ensure current character is LF */
        STRICT_CHECK(ch != LF);

        /* If have flag `F_TRAILING`.
         * It means end of a chunked request.
         */
        if (parser->flags & F_TRAILING) {
          /* Update state */
          /* End of a chunked request */
          UPDATE_STATE(s_message_done);

          /* Call callback */
          CALLBACK_NOTIFY_NOADVANCE(chunk_complete);

          /* Re-parse with new state */
          REEXECUTE();
        }
        /* If not have flag `F_TRAILING` */

        /* If have both `F_CHUNKED` and `F_CONTENTLENGTH` flags */
        /* Cannot use chunked encoding and a content-length header together
           per the HTTP specification. */
        if ((parser->flags & F_CHUNKED) &&
            (parser->flags & F_CONTENTLENGTH)) {
          /* Set error number */
          SET_ERRNO(HPE_UNEXPECTED_CONTENT_LENGTH);

          /* Goto error handler */
          goto error;
        }
        /* If not have both `F_CHUNKED` and `F_CONTENTLENGTH` flags */

        /* Update state */
        UPDATE_STATE(s_headers_done);

        /* Decide whether `upgrade` is on */
        /* Set this here so that on_headers_complete() callbacks can see it */
        parser->upgrade =
          ((parser->flags & (F_UPGRADE | F_CONNECTION_UPGRADE)) ==
           (F_UPGRADE | F_CONNECTION_UPGRADE) ||
           parser->method == HTTP_CONNECT);

        /* If have `on_headers_complete` callback */
        /* Here we call the headers_complete callback. This is somewhat
         * different than other callbacks because if the user returns 1, we
         * will interpret that as saying that this message has no body. This
         * is needed for the annoying case of recieving a response to a HEAD
         * request.
         *
         * We'd like to use CALLBACK_NOTIFY_NOADVANCE() here but we cannot, so
         * we have to simulate it by handling a change in errno below.
         */
        if (settings->on_headers_complete) {
          /* Call `on_headers_complete` callback */
          switch (settings->on_headers_complete(parser)) {
            /* If callback returns 0 */
            case 0:
              /* Do nothing */
              break;

            /* If callback returns 2.
             * It means to turn on `upgrade`, and skip body.
             */
            case 2:
              /* Set `upgrade` be 1 */
              parser->upgrade = 1;

              /* Fall through */

            /* If callback returns 1.
             * It means to skip body.
             */
            case 1:
              /* Add flag `F_SKIPBODY` */
              parser->flags |= F_SKIPBODY;
              break;

            /* If callback returns none of above */
            default:
              /* Set error number */
              SET_ERRNO(HPE_CB_headers_complete);

              /* Set parser state be current state.
               * Return parsed number of bytes.
               */
              RETURN(p - data); /* Error */
          }
        }

        /* If have error */
        if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
          /* Set parser state be current state.
           * Return parsed number of bytes.
           */
          RETURN(p - data);
        }
        /* If not have error */

        /* Re-parse with new state */
        REEXECUTE();
      }

      /* If current state is headers done */
      case s_headers_done:
      {
        /* Whether has body */
        int hasBody;

        /* Ensure current character is LF */
        STRICT_CHECK(ch != LF);

        /* Reset already-read counter */
        parser->nread = 0;

        /* Decide whether has body */
        hasBody = parser->flags & F_CHUNKED ||
          (parser->content_length > 0 && parser->content_length != ULLONG_MAX);

        /* If `upgrade` is on,
         * and not need process body.
         */
        if (parser->upgrade && (parser->method == HTTP_CONNECT ||
                                (parser->flags & F_SKIPBODY) || !hasBody)) {
          /* Exit, the rest of the message is in a different protocol. */
          /* Update state */
          UPDATE_STATE(NEW_MESSAGE());

          /* Call callback */
          CALLBACK_NOTIFY(message_complete);

          /* Set parser state be current state.
           * Return parsed number of bytes.
           */
          RETURN((p - data) + 1);
        }
        /* If `upgrade` is not on,
         * or need process body.
         */

        /* If `F_SKIPBODY` flag is on */
        if (parser->flags & F_SKIPBODY) {
          /* Update state */
          UPDATE_STATE(NEW_MESSAGE());

          /* Call callback */
          CALLBACK_NOTIFY(message_complete);
        /* If `F_SKIPBODY` flag is not on.
         * If `F_CHUNKED` flag is on.
         */
        } else if (parser->flags & F_CHUNKED) {
          /* chunked encoding - ignore Content-Length header */
          /* Update state */
          UPDATE_STATE(s_chunk_size_start);
        /* If `F_SKIPBODY` flag is not on.
         * If `F_CHUNKED` flag is not on.
         */
        } else {
          /* If unread content length is 0 */
          if (parser->content_length == 0) {
            /* Content-Length header given but zero: Content-Length: 0\r\n */
            /* Update state */
            UPDATE_STATE(NEW_MESSAGE());

            /* Call callback */
            CALLBACK_NOTIFY(message_complete);
          /* If unread content length is not 0 */
          } else if (parser->content_length != ULLONG_MAX) {
            /* Content-Length header given and non-zero */
            /* Update state */
            UPDATE_STATE(s_body_identity);
          /* If `Content-Length` header is not given */
          } else {
            /* If not need consume remaining data */
            if (!http_message_needs_eof(parser)) {
              /* Assume content-length 0 - read the next */
              /* Update state */
              UPDATE_STATE(NEW_MESSAGE());

              /* Call callback */
              CALLBACK_NOTIFY(message_complete);
            /* If need consume remaining data */
            } else {
              /* Read body until EOF */
              /* Update state */
              UPDATE_STATE(s_body_identity_eof);
            }
          }
        }

        break;
      }

      /* If current state is read body */
      case s_body_identity:
      {
        /* Get number of bytes to read */
        uint64_t to_read = MIN(parser->content_length,
                               (uint64_t) ((data + len) - p));

        /* Ensure content length is given and non-zero */
        assert(parser->content_length != 0
            && parser->content_length != ULLONG_MAX);

        /* Mark */
        /* The difference between advancing content_length and p is because
         * the latter will automaticaly advance on the next loop iteration.
         * Further, if content_length ends up at 0, we want to see the last
         * byte again for our message complete callback.
         */
        MARK(body);

        /* Deduct number of bytes to read from the unread content length */
        parser->content_length -= to_read;

        /* Move forward current character pointer */
        p += to_read - 1;

        /* If the unread content length is 0 */
        if (parser->content_length == 0) {
          /* Update state */
          UPDATE_STATE(s_message_done);

          /* Call callback */
          /* Mimic CALLBACK_DATA_NOADVANCE() but with one extra byte.
           *
           * The alternative to doing this is to wait for the next byte to
           * trigger the data callback, just as in every other case. The
           * problem with this is that this makes it difficult for the test
           * harness to distinguish between complete-on-EOF and
           * complete-on-length. It's not clear that this distinction is
           * important for applications, but let's keep it for now.
           */
          CALLBACK_DATA_(body, p - body_mark + 1, p - data);

          /* Re-parse with new state */
          REEXECUTE();
        }
        /* If the unread content length is not 0 */

        break;
      }

      /* If current state is consume remaining data */
      /* read until EOF */
      case s_body_identity_eof:
        /* Mark */
        MARK(body);

        /* Move forward current character pointer */
        p = data + len - 1;

        break;

      /* If current state is message done */
      case s_message_done:
        /* Update state */
        UPDATE_STATE(NEW_MESSAGE());

        /* Call callback */
        CALLBACK_NOTIFY(message_complete);

        /* If `upgrade` is on */
        if (parser->upgrade) {
          /* Set parser state be current state.
           * Return parsed number of bytes.
           */
          /* Exit, the rest of the message is in a different protocol. */
          RETURN((p - data) + 1);
        }
        /* If `upgrade` is not on */

        break;

      /* If current state is chunk size start */
      case s_chunk_size_start:
      {
        /* Ensure already-read counter is 1.
         * The 1 was incremented at the beginning of the for loop.
         */
        assert(parser->nread == 1);

        /* Ensure have flag `F_CHUNKED` */
        assert(parser->flags & F_CHUNKED);

        /* Map current character as hex digit to decimal value,
         * e.g. maps character 'A' to int 10.
         */
        unhex_val = unhex[(unsigned char)ch];

        /* If current character is not hex digit */
        if (UNLIKELY(unhex_val == -1)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);

          /* Goto error handler */
          goto error;
        }
        /* If current character is hex digit */

        /* Set unread content length */
        parser->content_length = unhex_val;

        /* Update state */
        UPDATE_STATE(s_chunk_size);

        /* Done with current character */
        break;
      }

      /* If current state is chunk size after met the first digit */
      case s_chunk_size:
      {
        /* Unread content length */
        uint64_t t;

        /* Ensure have flag `F_CHUNKED` */
        assert(parser->flags & F_CHUNKED);

        /* If current character is CR.
         * It means end of chunk size.
         */
        if (ch == CR) {
          /* Update state */
          UPDATE_STATE(s_chunk_size_almost_done);

          /* Done with current character */
          break;
        }
        /* If current character is not CR */

        /* Map current character as hex digit to decimal value,
         * e.g. maps character 'A' to int 10.
         */
        unhex_val = unhex[(unsigned char)ch];

        /* If current character is not hex digit */
        if (unhex_val == -1) {
          /* If current character is `;` or space.
           * It means chunk parameters.
           */
          if (ch == ';' || ch == ' ') {
            /* Update state */
            UPDATE_STATE(s_chunk_parameters);

            /* Done with current character */
            break;
          }
          /* If current character is not `;` or space */

          /* Set error number */
          SET_ERRNO(HPE_INVALID_CHUNK_SIZE);

          /* Goto error handler */
          goto error;
        }
        /* If current character is hex digit */

        /* Get unread content length */
        t = parser->content_length;

        /* Update unread content length */
        t *= 16;
        t += unhex_val;

        /* If unread content length is too large */
        /* Overflow? Test against a conservative limit for simplicity. */
        if (UNLIKELY((ULLONG_MAX - 16) / 16 < parser->content_length)) {
          /* Set error number */
          SET_ERRNO(HPE_INVALID_CONTENT_LENGTH);

          /* Goto error handler */
          goto error;
        }
        /* If unread content length is not too large */

        /* Set unread content length */
        parser->content_length = t;

        /* Done with current character */
        break;
      }

      /* If current state is chunk parameters */
      case s_chunk_parameters:
      {
        /* Ensure have flag `F_CHUNKED` */
        assert(parser->flags & F_CHUNKED);

        /* If current character is CR.
         * It means end of chunk parameters.
         */
        /* just ignore this shit. TODO check for overflow */
        if (ch == CR) {
          /* Update state */
          UPDATE_STATE(s_chunk_size_almost_done);

          /* Done with current character */
          break;
        }
        /* If current character is not CR */

        /* Done with current character */
        break;
      }

      /* If current state is chunk size almost done after met CR */
      case s_chunk_size_almost_done:
      {
        /* Ensure have flag `F_CHUNKED` */
        assert(parser->flags & F_CHUNKED);

        /* Ensure current character is LF */
        STRICT_CHECK(ch != LF);

        /* Reset already-read counter */
        parser->nread = 0;

        /* If unread content length is 0 */
        if (parser->content_length == 0) {
          /* Add flag */
          parser->flags |= F_TRAILING;

          /* Update state */
          UPDATE_STATE(s_header_field_start);
        /* If unread content length is not 0 */
        } else {
          /* Update state */
          UPDATE_STATE(s_chunk_data);
        }

        /* Call callback */
        CALLBACK_NOTIFY(chunk_header);

        /* Done with current character */
        break;
      }

      /* If current state is chunk data */
      case s_chunk_data:
      {
        /* Get number of bytes to read */
        uint64_t to_read = MIN(parser->content_length,
                               (uint64_t) ((data + len) - p));

        /* Ensure have flag `F_CHUNKED` */
        assert(parser->flags & F_CHUNKED);

        /* Ensure content length is given and non-zero */
        assert(parser->content_length != 0
            && parser->content_length != ULLONG_MAX);

        /* Mark */
        /* See the explanation in s_body_identity for why the content
         * length and data pointers are managed this way.
         */
        MARK(body);

        /* Deduct number of bytes to read from the unread content length */
        parser->content_length -= to_read;

        /* Move forward current character pointer */
        p += to_read - 1;

        /* If unread content length is 0 */
        if (parser->content_length == 0) {
          /* Update state */
          UPDATE_STATE(s_chunk_data_almost_done);
        }

        /* Done with current character */
        break;
      }

      /* If current state is chunk data almost done */
      case s_chunk_data_almost_done:
        /* Ensure have flag `F_CHUNKED` */
        assert(parser->flags & F_CHUNKED);

        /* Ensure unread content length is 0 */
        assert(parser->content_length == 0);

        /* Ensure current character is CR */
        STRICT_CHECK(ch != CR);

        /* Update state */
        UPDATE_STATE(s_chunk_data_done);

        /* Call callback */
        CALLBACK_DATA(body);

        /* Done with current character */
        break;

      /* If current state is chunk data done */
      case s_chunk_data_done:
        /* Ensure have flag `F_CHUNKED` */
        assert(parser->flags & F_CHUNKED);

        /* Ensure current character is LF */
        STRICT_CHECK(ch != LF);

        /* Reset already-read counter */
        parser->nread = 0;

        /* Update state */
        UPDATE_STATE(s_chunk_size_start);

        /* Call callback */
        CALLBACK_NOTIFY(chunk_complete);

        /* Done with current character */
        break;

      /* If current state is none of above */
      default:
        /* Assert error */
        assert(0 && "unhandled state");

        /* Set error number */
        SET_ERRNO(HPE_INVALID_INTERNAL_STATE);

        /* Goto error handler */
        goto error;
    }
  }

  /* Run callbacks for any marks that we have leftover after we ran our of
   * bytes. There should be at most one of these set, so it's OK to invoke
   * them in series (unset marks will not result in callbacks).
   *
   * We use the NOADVANCE() variety of callbacks here because 'p' has already
   * overflowed 'data' and this allows us to correct for the off-by-one that
   * we'd otherwise have (since CALLBACK_DATA() is meant to be run with a 'p'
   * value that's in-bounds).
   */

  /* Ensure at most one of these is marked */
  assert(((header_field_mark ? 1 : 0) +
          (header_value_mark ? 1 : 0) +
          (url_mark ? 1 : 0)  +
          (body_mark ? 1 : 0) +
          (status_mark ? 1 : 0)) <= 1);

  /* Call callback for the marked one */
  CALLBACK_DATA_NOADVANCE(header_field);
  CALLBACK_DATA_NOADVANCE(header_value);
  CALLBACK_DATA_NOADVANCE(url);
  CALLBACK_DATA_NOADVANCE(body);
  CALLBACK_DATA_NOADVANCE(status);

  /* Set parser state be current state.
   * Return parsed number of bytes.
   */
  RETURN(len);

/* Error handler */
error:
  /* If error number is not set */
  if (HTTP_PARSER_ERRNO(parser) == HPE_OK) {
    /* Set error number be `HPE_UNKNOWN` */
    SET_ERRNO(HPE_UNKNOWN);
  }

  /* Set parser state be current state.
   * Return parsed number of bytes.
   */
  RETURN(p - data);
}


/* Does the parser need to see an EOF to find the end of the message? */
int
http_message_needs_eof (const http_parser *parser)
{
  if (parser->type == HTTP_REQUEST) {
    return 0;
  }

  /* See RFC 2616 section 4.4 */
  if (parser->status_code / 100 == 1 || /* 1xx e.g. Continue */
      parser->status_code == 204 ||     /* No Content */
      parser->status_code == 304 ||     /* Not Modified */
      parser->flags & F_SKIPBODY) {     /* response to a HEAD request */
    return 0;
  }

  if ((parser->flags & F_CHUNKED) || parser->content_length != ULLONG_MAX) {
    return 0;
  }

  return 1;
}


int
http_should_keep_alive (const http_parser *parser)
{
  if (parser->http_major > 0 && parser->http_minor > 0) {
    /* HTTP/1.1 */
    if (parser->flags & F_CONNECTION_CLOSE) {
      return 0;
    }
  } else {
    /* HTTP/1.0 or earlier */
    if (!(parser->flags & F_CONNECTION_KEEP_ALIVE)) {
      return 0;
    }
  }

  return !http_message_needs_eof(parser);
}


const char *
http_method_str (enum http_method m)
{
  return ELEM_AT(method_strings, m, "<unknown>");
}


void
http_parser_init (http_parser *parser, enum http_parser_type t)
{
  /* Get `data` pointer */
  void *data = parser->data; /* preserve application data */

  /* Zeroize the `http_parser` struct */
  memset(parser, 0, sizeof(*parser));

  /* Set back `data` pointer */
  parser->data = data;

  /* Store parser type */
  parser->type = t;

  /* Set initial state */
  parser->state = (t == HTTP_REQUEST ? s_start_req : (t == HTTP_RESPONSE ? s_start_res : s_start_req_or_res));

  /* Set initial error number */
  parser->http_errno = HPE_OK;
}

void
http_parser_settings_init(http_parser_settings *settings)
{
  /* Zeroize the `http_parser_settings` struct */
  memset(settings, 0, sizeof(*settings));
}

const char *
http_errno_name(enum http_errno err) {
  assert(((size_t) err) < ARRAY_SIZE(http_strerror_tab));
  return http_strerror_tab[err].name;
}

const char *
http_errno_description(enum http_errno err) {
  assert(((size_t) err) < ARRAY_SIZE(http_strerror_tab));
  return http_strerror_tab[err].description;
}

static enum http_host_state
http_parse_host_char(enum http_host_state s, const char ch) {
  switch(s) {
    case s_http_userinfo:
    case s_http_userinfo_start:
      if (ch == '@') {
        return s_http_host_start;
      }

      if (IS_USERINFO_CHAR(ch)) {
        return s_http_userinfo;
      }
      break;

    case s_http_host_start:
      if (ch == '[') {
        return s_http_host_v6_start;
      }

      if (IS_HOST_CHAR(ch)) {
        return s_http_host;
      }

      break;

    case s_http_host:
      if (IS_HOST_CHAR(ch)) {
        return s_http_host;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_end:
      if (ch == ':') {
        return s_http_host_port_start;
      }

      break;

    case s_http_host_v6:
      if (ch == ']') {
        return s_http_host_v6_end;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_start:
      if (IS_HEX(ch) || ch == ':' || ch == '.') {
        return s_http_host_v6;
      }

      if (s == s_http_host_v6 && ch == '%') {
        return s_http_host_v6_zone_start;
      }
      break;

    case s_http_host_v6_zone:
      if (ch == ']') {
        return s_http_host_v6_end;
      }

    /* FALLTHROUGH */
    case s_http_host_v6_zone_start:
      /* RFC 6874 Zone ID consists of 1*( unreserved / pct-encoded) */
      if (IS_ALPHANUM(ch) || ch == '%' || ch == '.' || ch == '-' || ch == '_' ||
          ch == '~') {
        return s_http_host_v6_zone;
      }
      break;

    case s_http_host_port:
    case s_http_host_port_start:
      if (IS_NUM(ch)) {
        return s_http_host_port;
      }

      break;

    default:
      break;
  }
  return s_http_host_dead;
}

static int
http_parse_host(const char * buf, struct http_parser_url *u, int found_at) {
  enum http_host_state s;

  const char *p;
  size_t buflen = u->field_data[UF_HOST].off + u->field_data[UF_HOST].len;

  assert(u->field_set & (1 << UF_HOST));

  u->field_data[UF_HOST].len = 0;

  s = found_at ? s_http_userinfo_start : s_http_host_start;

  for (p = buf + u->field_data[UF_HOST].off; p < buf + buflen; p++) {
    enum http_host_state new_s = http_parse_host_char(s, *p);

    if (new_s == s_http_host_dead) {
      return 1;
    }

    switch(new_s) {
      case s_http_host:
        if (s != s_http_host) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_v6:
        if (s != s_http_host_v6) {
          u->field_data[UF_HOST].off = p - buf;
        }
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_v6_zone_start:
      case s_http_host_v6_zone:
        u->field_data[UF_HOST].len++;
        break;

      case s_http_host_port:
        if (s != s_http_host_port) {
          u->field_data[UF_PORT].off = p - buf;
          u->field_data[UF_PORT].len = 0;
          u->field_set |= (1 << UF_PORT);
        }
        u->field_data[UF_PORT].len++;
        break;

      case s_http_userinfo:
        if (s != s_http_userinfo) {
          u->field_data[UF_USERINFO].off = p - buf ;
          u->field_data[UF_USERINFO].len = 0;
          u->field_set |= (1 << UF_USERINFO);
        }
        u->field_data[UF_USERINFO].len++;
        break;

      default:
        break;
    }
    s = new_s;
  }

  /* Make sure we don't end somewhere unexpected */
  switch (s) {
    case s_http_host_start:
    case s_http_host_v6_start:
    case s_http_host_v6:
    case s_http_host_v6_zone_start:
    case s_http_host_v6_zone:
    case s_http_host_port_start:
    case s_http_userinfo:
    case s_http_userinfo_start:
      return 1;
    default:
      break;
  }

  return 0;
}

void
http_parser_url_init(struct http_parser_url *u) {
  memset(u, 0, sizeof(*u));
}

int
http_parser_parse_url(const char *buf, size_t buflen, int is_connect,
                      struct http_parser_url *u)
{
  enum state s;
  const char *p;
  enum http_parser_url_fields uf, old_uf;
  int found_at = 0;

  u->port = u->field_set = 0;
  s = is_connect ? s_req_server_start : s_req_spaces_before_url;
  old_uf = UF_MAX;

  for (p = buf; p < buf + buflen; p++) {
    s = parse_url_char(s, *p);

    /* Figure out the next field that we're operating on */
    switch (s) {
      case s_dead:
        return 1;

      /* Skip delimeters */
      case s_req_schema_slash:
      case s_req_schema_slash_slash:
      case s_req_server_start:
      case s_req_query_string_start:
      case s_req_fragment_start:
        continue;

      case s_req_schema:
        uf = UF_SCHEMA;
        break;

      case s_req_server_with_at:
        found_at = 1;

      /* FALLTROUGH */
      case s_req_server:
        uf = UF_HOST;
        break;

      case s_req_path:
        uf = UF_PATH;
        break;

      case s_req_query_string:
        uf = UF_QUERY;
        break;

      case s_req_fragment:
        uf = UF_FRAGMENT;
        break;

      default:
        assert(!"Unexpected state");
        return 1;
    }

    /* Nothing's changed; soldier on */
    if (uf == old_uf) {
      u->field_data[uf].len++;
      continue;
    }

    u->field_data[uf].off = p - buf;
    u->field_data[uf].len = 1;

    u->field_set |= (1 << uf);
    old_uf = uf;
  }

  /* host must be present if there is a schema */
  /* parsing http:///toto will fail */
  if ((u->field_set & (1 << UF_SCHEMA)) &&
      (u->field_set & (1 << UF_HOST)) == 0) {
    return 1;
  }

  if (u->field_set & (1 << UF_HOST)) {
    if (http_parse_host(buf, u, found_at) != 0) {
      return 1;
    }
  }

  /* CONNECT requests can only contain "hostname:port" */
  if (is_connect && u->field_set != ((1 << UF_HOST)|(1 << UF_PORT))) {
    return 1;
  }

  if (u->field_set & (1 << UF_PORT)) {
    /* Don't bother with endp; we've already validated the string */
    unsigned long v = strtoul(buf + u->field_data[UF_PORT].off, NULL, 10);

    /* Ports have a max value of 2^16 */
    if (v > 0xffff) {
      return 1;
    }

    u->port = (uint16_t) v;
  }

  return 0;
}

void
http_parser_pause(http_parser *parser, int paused) {
  /* Users should only be pausing/unpausing a parser that is not in an error
   * state. In non-debug builds, there's not much that we can do about this
   * other than ignore it.
   */
  if (HTTP_PARSER_ERRNO(parser) == HPE_OK ||
      HTTP_PARSER_ERRNO(parser) == HPE_PAUSED) {
    SET_ERRNO((paused) ? HPE_PAUSED : HPE_OK);
  } else {
    assert(0 && "Attempting to pause parser in error state");
  }
}

int
http_body_is_final(const struct http_parser *parser) {
    return parser->state == s_message_done;
}

unsigned long
http_parser_version(void) {
  return HTTP_PARSER_VERSION_MAJOR * 0x10000 |
         HTTP_PARSER_VERSION_MINOR * 0x00100 |
         HTTP_PARSER_VERSION_PATCH * 0x00001;
}
