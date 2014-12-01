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
#ifdef __SSE4_2__
# include <x86intrin.h>
#endif

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

struct state_ret {
  void* state;
  const char* result;
};

#define STATE(NAME) struct state_ret NAME(                           \
    http_parser* parser,                                             \
    const http_parser_settings* settings,                            \
    const char** marks,                                              \
    void* p_state,                                                   \
    char ch,                                                         \
    const char* p,                                                   \
    const char* end,                                                 \
    int8_t* n_err)

#define CALL_STATE(NAME) (NAME)(parser, settings, marks, p_state,    \
                                ch, p, end, n_err)

#define REDIRECT_STATE(FROM, TO) STATE(FROM) {                       \
  return CALL_STATE(TO);                                             \
}

typedef STATE((*state_cb));

#define CURRENT_STATE() ((state_cb) p_state)
#define UPDATE_STATE(V) p_state = (void*) (V)

#define IS_PARSING_DATA() (*n_err >> 2)
#define SET_PARSING_DATA() *n_err |= 0x4
#define CLEAR_PARSING_DATA() *n_err &= ~0x4

#define RETURN(V, E)                                                 \
do {                                                                 \
  struct state_ret ret;                                              \
  ret.state = (void*) CURRENT_STATE();                               \
  ret.result = (V);                                                  \
  if ((E) != 0) *n_err |= (E);                                       \
  return (ret);                                                      \
} while (0)

#define SKIP_ONE() RETURN(p + 1, 0)

#define TAIL(TO)                                                     \
do {                                                                 \
  if (LIKELY(p != end)) {                                            \
    ch = *p;                                                         \
    if (LIKELY(IS_PARSING_DATA() == 0))                              \
      if (!COUNT_HEADER_SIZE(1))                                     \
        RETURN_ERROR(HPE_HEADER_OVERFLOW);                           \
    return CALL_STATE(TO);                                           \
  }                                                                  \
  RETURN(p, 0);                                                      \
} while (0)

#define TAIL_SKIP_ONE(TO)                                            \
do {                                                                 \
  p++;                                                               \
  TAIL(TO);                                                          \
} while (0)

#define RETURN_ERROR(V)                                              \
do {                                                                 \
  SET_ERRNO(V);                                                      \
  RETURN(p - 1, 2);                                                  \
} while (0)

#define FINISH(V) RETURN(V, 1)

#define REEXECUTE() RETURN(p, 0)


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
      RETURN_ERROR(HPE_CB_##FOR);                                    \
    }                                                                \
    UPDATE_STATE(parser->state);                                     \
                                                                     \
    /* We either errored above or got paused; get out */             \
    if (UNLIKELY(HTTP_PARSER_ERRNO(parser) != HPE_OK)) {             \
      RETURN(ER, 2);                                                 \
    }                                                                \
  }                                                                  \
} while (0)

/* Run the notify callback FOR and consume the current byte */
#define CALLBACK_NOTIFY(FOR)            CALLBACK_NOTIFY_(FOR, p + 1)

/* Run the notify callback FOR and don't consume the current byte */
#define CALLBACK_NOTIFY_NOADVANCE(FOR)  CALLBACK_NOTIFY_(FOR, p)

/* Run data callback FOR with LEN bytes, returning ER if it fails */
#define CALLBACK_DATA_(FOR, LEN, ER)                                 \
do {                                                                 \
  assert(HTTP_PARSER_ERRNO(parser) == HPE_OK);                       \
                                                                     \
  if (MARK(FOR)) {                                                   \
    if (LIKELY(settings->on_##FOR)) {                                \
      parser->state = CURRENT_STATE();                               \
      if (UNLIKELY(0 !=                                              \
                   settings->on_##FOR(parser, MARK(FOR), (LEN)))) {  \
        RETURN_ERROR(HPE_CB_##FOR);                                  \
      }                                                              \
      UPDATE_STATE(parser->state);                                   \
                                                                     \
      /* We either errored above or got paused; get out */           \
      if (UNLIKELY(HTTP_PARSER_ERRNO(parser) != HPE_OK)) {           \
        RETURN(ER, 2);                                               \
      }                                                              \
    }                                                                \
    MARK(FOR) = NULL;                                                \
  }                                                                  \
} while (0)

/* Run the data callback FOR and consume the current byte */
#define CALLBACK_DATA(FOR)                                           \
    CALLBACK_DATA_(FOR, p - MARK(FOR), p + 1)

/* Run the data callback FOR and don't consume the current byte */
#define CALLBACK_DATA_NOADVANCE(FOR)                                 \
    CALLBACK_DATA_(FOR, p - MARK(FOR), p)

#define MARK(FOR) marks[FOR##_mark]

/* Set the mark FOR; non-destructive if mark is already set */
#define SET_MARK(FOR)                                                \
do {                                                                 \
  if (!MARK(FOR)) {                                                  \
    MARK(FOR) = p;                                                   \
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
  LIKELY((parser->nread += (V)) <= (HTTP_MAX_HEADER_SIZE))

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
#if HTTP_PARSER_STRICT
# define STOK 0
#else
# define STOK ' '
#endif

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
     STOK,      '!',      0,      '#',     '$',     '%',     '&',    '\'',
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

#undef STOK

#ifdef __SSE4_2__

static const char* sse_tokens =
#if HTTP_PARSER_STRICT
    "\x21\x27" /* '!' - '\'' */
#else
    "\x20\x27" /* ' ' - '\'' */
#endif
    "\x2a\x2e" /* '*' - '.' */
    "\x30\x39" /* '0' - '9' */
    "\x61\x7a" /* 'a' - 'z' */
    "\x5e\x60" /* '^' - '`' */
    "\x41\x5a" /* 'A' - 'Z' */
    "\x7c\x7c" /* '|' */
    "\x7e\x7e" /* '~' */;

#endif

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

#define STATE_ENUM(V)                                                \
    V(s_dead)                                                        \
    V(s_start_req_or_res)                                            \
    V(s_res_or_resp_H)                                               \
    V(s_start_res)                                                   \
    V(s_res_H)                                                       \
    V(s_res_HT)                                                      \
    V(s_res_HTT)                                                     \
    V(s_res_HTTP)                                                    \
    V(s_res_first_http_major)                                        \
    V(s_res_http_major)                                              \
    V(s_res_first_http_minor)                                        \
    V(s_res_http_minor)                                              \
    V(s_res_first_status_code)                                       \
    V(s_res_status_code)                                             \
    V(s_res_status_start)                                            \
    V(s_res_status)                                                  \
    V(s_res_line_almost_done)                                        \
    V(s_start_req)                                                   \
    V(s_req_method)                                                  \
    V(s_req_spaces_before_url)                                       \
    V(s_req_schema)                                                  \
    V(s_req_schema_slash)                                            \
    V(s_req_schema_slash_slash)                                      \
    V(s_req_server_start)                                            \
    V(s_req_server)                                                  \
    V(s_req_server_with_at)                                          \
    V(s_req_path)                                                    \
    V(s_req_query_string_start)                                      \
    V(s_req_query_string)                                            \
    V(s_req_fragment_start)                                          \
    V(s_req_fragment)                                                \
    V(s_req_http_start)                                              \
    V(s_req_http_H)                                                  \
    V(s_req_http_HT)                                                 \
    V(s_req_http_HTT)                                                \
    V(s_req_http_HTTP)                                               \
    V(s_req_first_http_major)                                        \
    V(s_req_http_major)                                              \
    V(s_req_first_http_minor)                                        \
    V(s_req_http_minor)                                              \
    V(s_req_line_almost_done)                                        \
    V(s_header_field_start)                                          \
    V(s_header_field)                                                \
    V(s_header_value_discard_ws)                                     \
    V(s_header_value_discard_ws_almost_done)                         \
    V(s_header_value_discard_lws)                                    \
    V(s_header_value_start)                                          \
    V(s_header_value)                                                \
    V(s_header_value_lws)                                            \
    V(s_header_almost_done)                                          \
    V(s_chunk_size_start)                                            \
    V(s_chunk_size)                                                  \
    V(s_chunk_parameters)                                            \
    V(s_chunk_size_almost_done)                                      \
    V(s_headers_almost_done)                                         \
    V(s_headers_done)                                                \
    V(s_chunk_data)                                                  \
    V(s_chunk_data_almost_done)                                      \
    V(s_chunk_data_done)                                             \
    V(s_body_identity)                                               \
    V(s_body_identity_eof)                                           \
    V(s_message_done)


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
  , h_matching_connection_keep_alive
  , h_matching_connection_close

  , h_transfer_encoding_chunked
  , h_connection_keep_alive
  , h_connection_close
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
  , s_http_host_port_start
  , s_http_host_port
};

enum marks {
  header_field_mark,
  header_value_mark,
  value_mark,
  url_mark,
  body_mark,
  status_mark,
  max_mark
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

#define TOKEN(c)            (tokens[(unsigned char)c])

#if HTTP_PARSER_STRICT
#define IS_URL_CHAR(c)      (BIT_AT(normal_url_char, (unsigned char)c))
#define IS_HOST_CHAR(c)     (IS_ALPHANUM(c) || (c) == '.' || (c) == '-')
#else
#define IS_URL_CHAR(c)                                                         \
  (BIT_AT(normal_url_char, (unsigned char)c) || ((c) & 0x80))
#define IS_HOST_CHAR(c)                                                        \
  (IS_ALPHANUM(c) || (c) == '.' || (c) == '-' || (c) == '_')
#endif


#define start_state (parser->type == HTTP_REQUEST ? s_start_req : s_start_res)


#if HTTP_PARSER_STRICT
# define STRICT_CHECK(cond)                                          \
do {                                                                 \
  if (cond) {                                                        \
    RETURN_ERROR(HPE_STRICT);                                        \
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

/* Forward declarations for all states */
#define STATE_FORWARD_DECL(V) static STATE(V);
STATE_ENUM(STATE_FORWARD_DECL)
#undef STATE_FORWARD_DECL

static state_cb parse_url_char(state_cb s, const char ch);

#ifdef __SSE4_2__

const char* find_cr_or_lf(const char* p, const char* end) {
  __m128i ranges;
  size_t size;
  const char* aligned_end;

  size = end - p;
  size &= ~0xf;
  aligned_end = p + size;

  ranges = _mm_loadu_si128((const __m128i*) "\r\n");
  for (; p != aligned_end; p += 16) {
    __m128i p128;
    int pos;

    p128 = _mm_loadu_si128((const __m128i*) p);

    pos = _mm_cmpestri(
        ranges,
        2,
        p128,
        16,
        _SIDD_UBYTE_OPS | _SIDD_LEAST_SIGNIFICANT | _SIDD_CMP_EQUAL_ANY);
    if (UNLIKELY(pos != 16))
      return p + pos;
  }

  /* Slow search */
  for (; p != end; p++)
    if (*p == '\r' || *p == '\n')
      return p;
  return end;
}

const char* find_non_token(const char* p, const char* end) {
  __m128i ranges;
  size_t size;
  const char* aligned_end;

  size = end - p;
  size &= ~0xf;
  aligned_end = p + size;

  ranges = _mm_loadu_si128((const __m128i*) sse_tokens);
  for (; p != aligned_end; p += 16) {
    __m128i p128;
    int pos;

    p128 = _mm_loadu_si128((const __m128i*) p);

    pos = _mm_cmpestri(
        ranges,
        16,
        p128,
        16,
        _SIDD_UBYTE_OPS |
            _SIDD_LEAST_SIGNIFICANT |
            _SIDD_CMP_RANGES |
            _SIDD_NEGATIVE_POLARITY);
    if (UNLIKELY(pos != 16))
      return p + pos;
  }

  /* Slow search */
  for (; p != end; p++)
    if (!TOKEN(*p))
      return p;
  return end;
}

#endif

STATE(s_dead) {
  /* this state is used after a 'Connection: close' message
   * the parser will error out if it reads another message
   */
  if (LIKELY(ch == CR || ch == LF))
    SKIP_ONE();

  RETURN_ERROR(HPE_CLOSED_CONNECTION);
}

STATE(s_start_req_or_res) {
  if (ch == CR || ch == LF)
    SKIP_ONE();

  parser->flags = 0;
  parser->content_length = ULLONG_MAX;

  if (ch == 'H') {
    UPDATE_STATE(s_res_or_resp_H);
    CALLBACK_NOTIFY(message_begin);
    SKIP_ONE();
  }

  parser->type = HTTP_REQUEST;
  UPDATE_STATE(s_start_req);
  REEXECUTE();
}

STATE(s_res_or_resp_H) {
  if (ch == 'T') {
    parser->type = HTTP_RESPONSE;
    UPDATE_STATE(s_res_HT);
  } else {
    if (UNLIKELY(ch != 'E'))
      RETURN_ERROR(HPE_INVALID_CONSTANT);

    parser->type = HTTP_REQUEST;
    parser->method = HTTP_HEAD;
    parser->index = 2;
    UPDATE_STATE(s_req_method);
  }
  SKIP_ONE();
}

STATE(s_start_res) {
  parser->flags = 0;
  parser->content_length = ULLONG_MAX;

  switch (ch) {
    case 'H':
      UPDATE_STATE(s_res_H);
      break;

    case CR:
    case LF:
      break;

    default:
      RETURN_ERROR(HPE_INVALID_CONSTANT);
  }

  CALLBACK_NOTIFY(message_begin);
  SKIP_ONE();
}

STATE(s_res_H) {
  STRICT_CHECK(ch != 'T');
  UPDATE_STATE(s_res_HT);
  SKIP_ONE();
}

STATE(s_res_HT) {
  STRICT_CHECK(ch != 'T');
  UPDATE_STATE(s_res_HTT);
  SKIP_ONE();
}

STATE(s_res_HTT) {
  STRICT_CHECK(ch != 'P');
  UPDATE_STATE(s_res_HTTP);
  SKIP_ONE();
}

STATE(s_res_HTTP) {
  STRICT_CHECK(ch != '/');
  UPDATE_STATE(s_res_first_http_major);
  SKIP_ONE();
}

STATE(s_res_first_http_major) {
  if (UNLIKELY(ch < '0' || ch > '9')) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_major = ch - '0';
  UPDATE_STATE(s_res_http_major);
  SKIP_ONE();
}

/* major HTTP version or dot */
STATE(s_res_http_major) {
  if (ch == '.') {
    UPDATE_STATE(s_res_first_http_minor);
    SKIP_ONE();
  }

  if (!IS_NUM(ch)) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_major *= 10;
  parser->http_major += ch - '0';

  if (UNLIKELY(parser->http_major > 999)) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  SKIP_ONE();
}

/* first digit of minor HTTP version */
STATE(s_res_first_http_minor) {
  if (UNLIKELY(!IS_NUM(ch))) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_minor = ch - '0';
  UPDATE_STATE(s_res_http_minor);
  SKIP_ONE();
}

/* minor HTTP version or end of request line */
STATE(s_res_http_minor) {
  if (ch == ' ') {
    UPDATE_STATE(s_res_first_status_code);
    SKIP_ONE();
  }

  if (UNLIKELY(!IS_NUM(ch))) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_minor *= 10;
  parser->http_minor += ch - '0';

  if (UNLIKELY(parser->http_minor > 999)) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  SKIP_ONE();
}

STATE(s_res_first_status_code) {
  if (!IS_NUM(ch)) {
    if (ch == ' ') {
      SKIP_ONE();
    }

    RETURN_ERROR(HPE_INVALID_STATUS);
  }
  parser->status_code = ch - '0';
  UPDATE_STATE(s_res_status_code);
  SKIP_ONE();
}

STATE(s_res_status_code) {
  if (!IS_NUM(ch)) {
    switch (ch) {
      case ' ':
        UPDATE_STATE(s_res_status_start);
        break;
      case CR:
        UPDATE_STATE(s_res_line_almost_done);
        break;
      case LF:
        UPDATE_STATE(s_header_field_start);
        break;
      default:
        RETURN_ERROR(HPE_INVALID_STATUS);
    }
    SKIP_ONE();
  }

  parser->status_code *= 10;
  parser->status_code += ch - '0';

  if (UNLIKELY(parser->status_code > 999)) {
    RETURN_ERROR(HPE_INVALID_STATUS);
  }

  SKIP_ONE();
}

STATE(s_res_status_start) {
  if (ch == CR) {
    UPDATE_STATE(s_res_line_almost_done);
    SKIP_ONE();
  }

  if (ch == LF) {
    UPDATE_STATE(s_header_field_start);
    SKIP_ONE();
  }

  SET_MARK(status);
  UPDATE_STATE(s_res_status);
  parser->index = 0;
  SKIP_ONE();
}

STATE(s_res_status) {
  if (ch == CR) {
    UPDATE_STATE(s_res_line_almost_done);
    CALLBACK_DATA(status);
  } else if (ch == LF) {
    UPDATE_STATE(s_header_field_start);
    CALLBACK_DATA(status);
  }

  SKIP_ONE();
}

STATE(s_res_line_almost_done) {
  STRICT_CHECK(ch != LF);
  UPDATE_STATE(s_header_field_start);
  SKIP_ONE();
}

STATE(s_start_req) {
  if (ch == CR || ch == LF)
    SKIP_ONE();
  parser->flags = 0;
  parser->content_length = ULLONG_MAX;

  if (UNLIKELY(!IS_ALPHA(ch))) {
    RETURN_ERROR(HPE_INVALID_METHOD);
  }

  parser->method = (enum http_method) 0;
  parser->index = 1;
  switch (ch) {
    case 'C': parser->method = HTTP_CONNECT; /* or COPY, CHECKOUT */ break;
    case 'D': parser->method = HTTP_DELETE; break;
    case 'G': parser->method = HTTP_GET; break;
    case 'H': parser->method = HTTP_HEAD; break;
    case 'L': parser->method = HTTP_LOCK; break;
    case 'M': parser->method = HTTP_MKCOL; /* or MOVE, MKACTIVITY, MERGE, M-SEARCH, MKCALENDAR */ break;
    case 'N': parser->method = HTTP_NOTIFY; break;
    case 'O': parser->method = HTTP_OPTIONS; break;
    case 'P': parser->method = HTTP_POST;
      /* or PROPFIND|PROPPATCH|PUT|PATCH|PURGE */
      break;
    case 'R': parser->method = HTTP_REPORT; break;
    case 'S': parser->method = HTTP_SUBSCRIBE; /* or SEARCH */ break;
    case 'T': parser->method = HTTP_TRACE; break;
    case 'U': parser->method = HTTP_UNLOCK; /* or UNSUBSCRIBE */ break;
    default:
      RETURN_ERROR(HPE_INVALID_METHOD);
  }
  UPDATE_STATE(s_req_method);

  CALLBACK_NOTIFY(message_begin);

  SKIP_ONE();
}

STATE(s_req_method) {
  const char* start = p;
  const char* matcher;
  unsigned int index = parser->index;
  for (; p != end && CURRENT_STATE() == s_req_method; p++) {
    matcher = method_strings[parser->method];
    ch = *p;

    if (UNLIKELY(ch == '\0')) {
      RETURN_ERROR(HPE_INVALID_METHOD);
    }

    if (ch == ' ' && matcher[index] == '\0') {
      UPDATE_STATE(s_req_spaces_before_url);
    } else if (ch == matcher[index]) {
      ; /* nada */
    } else if (parser->method == HTTP_CONNECT) {
      if (index == 1 && ch == 'H') {
        parser->method = HTTP_CHECKOUT;
      } else if (index == 2  && ch == 'P') {
        parser->method = HTTP_COPY;
      } else {
        RETURN_ERROR(HPE_INVALID_METHOD);
      }
    } else if (parser->method == HTTP_MKCOL) {
      if (index == 1 && ch == 'O') {
        parser->method = HTTP_MOVE;
      } else if (index == 1 && ch == 'E') {
        parser->method = HTTP_MERGE;
      } else if (index == 1 && ch == '-') {
        parser->method = HTTP_MSEARCH;
      } else if (index == 2 && ch == 'A') {
        parser->method = HTTP_MKACTIVITY;
      } else if (index == 3 && ch == 'A') {
        parser->method = HTTP_MKCALENDAR;
      } else {
        RETURN_ERROR(HPE_INVALID_METHOD);
      }
    } else if (parser->method == HTTP_SUBSCRIBE) {
      if (index == 1 && ch == 'E') {
        parser->method = HTTP_SEARCH;
      } else {
        RETURN_ERROR(HPE_INVALID_METHOD);
      }
    } else if (index == 1 && parser->method == HTTP_POST) {
      if (ch == 'R') {
        parser->method = HTTP_PROPFIND; /* or HTTP_PROPPATCH */
      } else if (ch == 'U') {
        parser->method = HTTP_PUT; /* or HTTP_PURGE */
      } else if (ch == 'A') {
        parser->method = HTTP_PATCH;
      } else {
        RETURN_ERROR(HPE_INVALID_METHOD);
      }
    } else if (index == 2) {
      if (parser->method == HTTP_PUT) {
        if (ch == 'R') {
          parser->method = HTTP_PURGE;
        } else {
          RETURN_ERROR(HPE_INVALID_METHOD);
        }
      } else if (parser->method == HTTP_UNLOCK) {
        if (ch == 'S') {
          parser->method = HTTP_UNSUBSCRIBE;
        } else {
          RETURN_ERROR(HPE_INVALID_METHOD);
        }
      } else {
        RETURN_ERROR(HPE_INVALID_METHOD);
      }
    } else if (index == 4 &&
               parser->method == HTTP_PROPFIND &&
               ch == 'P') {
      parser->method = HTTP_PROPPATCH;
    } else {
      RETURN_ERROR(HPE_INVALID_METHOD);
    }

    ++index;
  }
  parser->index = index;

  if (!COUNT_HEADER_SIZE(p - start))
    RETURN_ERROR(HPE_HEADER_OVERFLOW);

  REEXECUTE();
}

STATE(s_req_spaces_before_url) {
  if (ch == ' ') {
    SKIP_ONE();
  }

  SET_MARK(url);
  if (parser->method == HTTP_CONNECT) {
    UPDATE_STATE(s_req_server_start);
  }

  UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
  if (UNLIKELY(CURRENT_STATE() == s_dead)) {
    RETURN_ERROR(HPE_INVALID_URL);
  }

  SKIP_ONE();
}

REDIRECT_STATE(s_req_schema, s_req_server_start)
REDIRECT_STATE(s_req_schema_slash, s_req_server_start)
REDIRECT_STATE(s_req_schema_slash_slash, s_req_server_start)
STATE(s_req_server_start) {
  switch (ch) {
    /* No whitespace allowed here */
    case ' ':
    case CR:
    case LF:
      RETURN_ERROR(HPE_INVALID_URL);
    default:
      UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
      if (UNLIKELY(CURRENT_STATE() == s_dead)) {
        RETURN_ERROR(HPE_INVALID_URL);
      }
  }

  SKIP_ONE();
}

REDIRECT_STATE(s_req_server, s_req_fragment)
REDIRECT_STATE(s_req_server_with_at, s_req_fragment)
REDIRECT_STATE(s_req_path, s_req_fragment)
REDIRECT_STATE(s_req_query_string_start, s_req_fragment)
REDIRECT_STATE(s_req_query_string, s_req_fragment)
REDIRECT_STATE(s_req_fragment_start, s_req_fragment)
STATE(s_req_fragment) {
  switch (ch) {
    case ' ':
      UPDATE_STATE(s_req_http_start);
      CALLBACK_DATA(url);
      break;
    case CR:
    case LF:
      parser->http_major = 0;
      parser->http_minor = 9;
      UPDATE_STATE((ch == CR) ?
        s_req_line_almost_done :
        s_header_field_start);
      CALLBACK_DATA(url);
      break;
    default:
      UPDATE_STATE(parse_url_char(CURRENT_STATE(), ch));
      if (UNLIKELY(CURRENT_STATE() == s_dead)) {
        RETURN_ERROR(HPE_INVALID_URL);
      }
  }
  SKIP_ONE();
}

STATE(s_req_http_start) {
  switch (ch) {
    case 'H':
      UPDATE_STATE(s_req_http_H);
      break;
    case ' ':
      break;
    default:
      RETURN_ERROR(HPE_INVALID_CONSTANT);
  }
  SKIP_ONE();
}

STATE(s_req_http_H) {
  STRICT_CHECK(ch != 'T');
  UPDATE_STATE(s_req_http_HT);
  SKIP_ONE();
}

STATE(s_req_http_HT) {
  STRICT_CHECK(ch != 'T');
  UPDATE_STATE(s_req_http_HTT);
  SKIP_ONE();
}

STATE(s_req_http_HTT) {
  STRICT_CHECK(ch != 'P');
  UPDATE_STATE(s_req_http_HTTP);
  SKIP_ONE();
}

STATE(s_req_http_HTTP) {
  STRICT_CHECK(ch != '/');
  UPDATE_STATE(s_req_first_http_major);
  SKIP_ONE();
}

/* first digit of major HTTP version */
STATE(s_req_first_http_major) {
  if (UNLIKELY(ch < '1' || ch > '9')) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_major = ch - '0';
  UPDATE_STATE(s_req_http_major);
  SKIP_ONE();
}

/* major HTTP version or dot */
STATE(s_req_http_major) {
  if (ch == '.') {
    UPDATE_STATE(s_req_first_http_minor);
    SKIP_ONE();
  }

  if (UNLIKELY(!IS_NUM(ch))) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_major *= 10;
  parser->http_major += ch - '0';

  if (UNLIKELY(parser->http_major > 999)) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  SKIP_ONE();
}

/* first digit of minor HTTP version */
STATE(s_req_first_http_minor) {
  if (UNLIKELY(!IS_NUM(ch))) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_minor = ch - '0';
  UPDATE_STATE(s_req_http_minor);
  SKIP_ONE();
}

/* minor HTTP version or end of request line */
STATE(s_req_http_minor) {
  if (ch == CR) {
    UPDATE_STATE(s_req_line_almost_done);
    SKIP_ONE();
  }

  if (ch == LF) {
    UPDATE_STATE(s_header_field_start);
    SKIP_ONE();
  }

  /* XXX allow spaces after digit? */

  if (UNLIKELY(!IS_NUM(ch))) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  parser->http_minor *= 10;
  parser->http_minor += ch - '0';

  if (UNLIKELY(parser->http_minor > 999)) {
    RETURN_ERROR(HPE_INVALID_VERSION);
  }

  SKIP_ONE();
}

/* end of request line */
STATE(s_req_line_almost_done) {
  if (UNLIKELY(ch != LF)) {
    RETURN_ERROR(HPE_LF_EXPECTED);
  }

  UPDATE_STATE(s_header_field_start);
  SKIP_ONE();
}

STATE(s_header_field_start) {
  char c;

  if (ch == CR) {
    UPDATE_STATE(s_headers_almost_done);
    SKIP_ONE();
  }

  if (UNLIKELY(ch == LF)) {
    /* they might be just sending \n instead of \r\n so this would be
     * the second \n to denote the end of headers*/
    UPDATE_STATE(s_headers_almost_done);
    REEXECUTE();
  }

  c = TOKEN(ch);

  if (UNLIKELY(!c)) {
    RETURN_ERROR(HPE_INVALID_HEADER_TOKEN);
  }

  SET_MARK(header_field);

  parser->index = 0;
  UPDATE_STATE(s_header_field);

  switch (c) {
    case 'c':
      parser->header_state = h_C;
      break;

    case 'p':
      parser->header_state = h_matching_proxy_connection;
      break;

    case 't':
      parser->header_state = h_matching_transfer_encoding;
      break;

    case 'u':
      parser->header_state = h_matching_upgrade;
      break;

    default:
      parser->header_state = h_general;
      break;
  }
  SKIP_ONE();
}

STATE(s_header_field) {
  char c;
  const char* start = p;
  for (; p != end; p++) {
    ch = *p;
    c = TOKEN(ch);

    if (!c)
      break;

    switch (parser->header_state) {
      case h_general:
#ifdef __SSE4_2__
        p = find_non_token(p, end) - 1;
#endif
        break;

      case h_C:
        parser->index++;
        parser->header_state = (c == 'o' ? h_CO : h_general);
        break;

      case h_CO:
        parser->index++;
        parser->header_state = (c == 'n' ? h_CON : h_general);
        break;

      case h_CON:
        parser->index++;
        switch (c) {
          case 'n':
            parser->header_state = h_matching_connection;
            break;
          case 't':
            parser->header_state = h_matching_content_length;
            break;
          default:
            parser->header_state = h_general;
            break;
        }
        break;

      /* connection */

      case h_matching_connection:
        parser->index++;
        if (parser->index > sizeof(CONNECTION)-1
            || c != CONNECTION[parser->index]) {
          parser->header_state = h_general;
        } else if (parser->index == sizeof(CONNECTION)-2) {
          parser->header_state = h_connection;
        }
        break;

      /* proxy-connection */

      case h_matching_proxy_connection:
        parser->index++;
        if (parser->index > sizeof(PROXY_CONNECTION)-1
            || c != PROXY_CONNECTION[parser->index]) {
          parser->header_state = h_general;
        } else if (parser->index == sizeof(PROXY_CONNECTION)-2) {
          parser->header_state = h_connection;
        }
        break;

      /* content-length */

      case h_matching_content_length:
        parser->index++;
        if (parser->index > sizeof(CONTENT_LENGTH)-1
            || c != CONTENT_LENGTH[parser->index]) {
          parser->header_state = h_general;
        } else if (parser->index == sizeof(CONTENT_LENGTH)-2) {
          parser->header_state = h_content_length;
        }
        break;

      /* transfer-encoding */

      case h_matching_transfer_encoding:
        parser->index++;
        if (parser->index > sizeof(TRANSFER_ENCODING)-1
            || c != TRANSFER_ENCODING[parser->index]) {
          parser->header_state = h_general;
        } else if (parser->index == sizeof(TRANSFER_ENCODING)-2) {
          parser->header_state = h_transfer_encoding;
        }
        break;

      /* upgrade */

      case h_matching_upgrade:
        parser->index++;
        if (parser->index > sizeof(UPGRADE)-1
            || c != UPGRADE[parser->index]) {
          parser->header_state = h_general;
        } else if (parser->index == sizeof(UPGRADE)-2) {
          parser->header_state = h_upgrade;
        }
        break;

      case h_connection:
      case h_content_length:
      case h_transfer_encoding:
      case h_upgrade:
        if (ch != ' ') parser->header_state = h_general;
        break;

      default:
        assert(0 && "Unknown header_state");
        break;
    }
  }

  if (!COUNT_HEADER_SIZE(p - start))
    RETURN_ERROR(HPE_HEADER_OVERFLOW);

  if (p == end) {
    REEXECUTE();
  }

  if (ch == ':') {
    UPDATE_STATE(s_header_value_discard_ws);
    CALLBACK_DATA(header_field);
    SKIP_ONE();
  }

  RETURN_ERROR(HPE_INVALID_HEADER_TOKEN);
}

STATE(s_header_value_discard_ws) {
  for (; p != end; p++) {
    ch = *p;
    switch (ch) {
      case ' ':
      case '\t':
        break;
      case CR:
        UPDATE_STATE(s_header_value_discard_ws_almost_done);
        SKIP_ONE();
      case LF:
        UPDATE_STATE(s_header_value_discard_lws);
        TAIL_SKIP_ONE(s_header_value_discard_lws);
      default:
        return CALL_STATE(s_header_value_start);
    }
  }
  REEXECUTE();
}

STATE(s_header_value_start) {
  char c;

  SET_MARK(header_value);

  UPDATE_STATE(s_header_value);
  parser->index = 0;

  c = LOWER(ch);

  switch (parser->header_state) {
    case h_upgrade:
      parser->flags |= F_UPGRADE;
      parser->header_state = h_general;
      break;

    case h_transfer_encoding:
      /* looking for 'Transfer-Encoding: chunked' */
      if ('c' == c) {
        parser->header_state = h_matching_transfer_encoding_chunked;
      } else {
        parser->header_state = h_general;
      }
      break;

    case h_content_length:
      if (UNLIKELY(!IS_NUM(ch))) {
        RETURN_ERROR(HPE_INVALID_CONTENT_LENGTH);
      }

      parser->content_length = ch - '0';
      break;

    case h_connection:
      /* looking for 'Connection: keep-alive' */
      if (c == 'k') {
        parser->header_state = h_matching_connection_keep_alive;
      /* looking for 'Connection: close' */
      } else if (c == 'c') {
        parser->header_state = h_matching_connection_close;
      } else {
        parser->header_state = h_general;
      }
      break;

    default:
      parser->header_state = h_general;
      break;
  }
  SKIP_ONE();
}

STATE(s_header_value) {
  char c;
  const char* start = p;
  enum header_states h_state = parser->header_state;
  enum header_states h_initial = h_state;
  for (; p != end; p++) {
    ch = *p;
    if (ch == CR) {
      UPDATE_STATE(s_header_almost_done);
      parser->header_state = h_state;
      CALLBACK_DATA(header_value);
      break;
    }

    if (UNLIKELY(ch == LF)) {
      UPDATE_STATE(s_header_almost_done);
      if (!COUNT_HEADER_SIZE(p - start))
        RETURN_ERROR(HPE_HEADER_OVERFLOW);
      parser->header_state = h_state;
      CALLBACK_DATA_NOADVANCE(header_value);
      REEXECUTE();
    }

    c = LOWER(ch);

    switch (h_state) {
      case h_general:
      {
#ifdef __SSE4_2__
        p = find_cr_or_lf(p, end);
#else
        const char* p_cr;
        const char* p_lf;
        size_t limit = end - p;

        limit = MIN(limit, HTTP_MAX_HEADER_SIZE);

        p_cr = memchr(p, CR, limit);
        p_lf = memchr(p, LF, limit);
        if (p_cr != NULL) {
          if (p_lf != NULL && p_cr >= p_lf)
            p = p_lf;
          else
            p = p_cr;
        } else if (UNLIKELY(p_lf != NULL)) {
          p = p_lf;
        } else {
          p = end;
        }
#endif
        --p;

        break;
      }

      case h_connection:
      case h_transfer_encoding:
        assert(0 && "Shouldn't get here.");
        break;

      case h_content_length:
      {
        uint64_t t;

        if (ch == ' ') break;

        if (UNLIKELY(!IS_NUM(ch))) {
          parser->header_state = h_state;
          RETURN_ERROR(HPE_INVALID_CONTENT_LENGTH);
        }

        t = parser->content_length;
        t *= 10;
        t += ch - '0';

        /* Overflow? Test against a conservative limit for simplicity. */
        if (UNLIKELY((ULLONG_MAX - 10) / 10 < parser->content_length)) {
          parser->header_state = h_state;
          RETURN_ERROR(HPE_INVALID_CONTENT_LENGTH);
        }

        parser->content_length = t;
        break;
      }

      /* Transfer-Encoding: chunked */
      case h_matching_transfer_encoding_chunked:
        parser->index++;
        if (parser->index > sizeof(CHUNKED)-1
            || c != CHUNKED[parser->index]) {
          h_state = h_general;
        } else if (parser->index == sizeof(CHUNKED)-2) {
          h_state = h_transfer_encoding_chunked;
        }
        break;

      /* looking for 'Connection: keep-alive' */
      case h_matching_connection_keep_alive:
        parser->index++;
        if (parser->index > sizeof(KEEP_ALIVE)-1
            || c != KEEP_ALIVE[parser->index]) {
          h_state = h_general;
        } else if (parser->index == sizeof(KEEP_ALIVE)-2) {
          h_state = h_connection_keep_alive;
        }
        break;

      /* looking for 'Connection: close' */
      case h_matching_connection_close:
        parser->index++;
        if (parser->index > sizeof(CLOSE)-1 || c != CLOSE[parser->index]) {
          h_state = h_general;
        } else if (parser->index == sizeof(CLOSE)-2) {
          h_state = h_connection_close;
        }
        break;

      case h_transfer_encoding_chunked:
      case h_connection_keep_alive:
      case h_connection_close:
        if (ch != ' ') h_state = h_general;
        break;

      default:
        UPDATE_STATE(s_header_value);
        h_state = h_general;
        break;
    }
  }
  if (h_initial != h_state)
    parser->header_state = h_state;

  if (!COUNT_HEADER_SIZE(p - start))
    RETURN_ERROR(HPE_HEADER_OVERFLOW);

  if (p == end)
    REEXECUTE();
  else
    SKIP_ONE();
}

STATE(s_header_almost_done) {
  STRICT_CHECK(ch != LF);

  UPDATE_STATE(s_header_value_lws);
  SKIP_ONE();
}

STATE(s_header_value_lws) {
  if (ch == ' ' || ch == '\t') {
    UPDATE_STATE(s_header_value_start);
    REEXECUTE();
  }

  /* finished the header */
  switch (parser->header_state) {
    case h_connection_keep_alive:
      parser->flags |= F_CONNECTION_KEEP_ALIVE;
      break;
    case h_connection_close:
      parser->flags |= F_CONNECTION_CLOSE;
      break;
    case h_transfer_encoding_chunked:
      parser->flags |= F_CHUNKED;
      break;
    default:
      break;
  }

  UPDATE_STATE(s_header_field_start);
  REEXECUTE();
}

STATE(s_header_value_discard_ws_almost_done) {
  STRICT_CHECK(ch != LF);
  UPDATE_STATE(s_header_value_discard_lws);
  SKIP_ONE();
}

STATE(s_header_value_discard_lws) {
  if (ch == ' ' || ch == '\t') {
    UPDATE_STATE(s_header_value_discard_ws);
    SKIP_ONE();
  } else {
    /* header value was empty */
    SET_MARK(header_value);
    UPDATE_STATE(s_header_field_start);
    CALLBACK_DATA_NOADVANCE(header_value);
    REEXECUTE();
  }
}

STATE(s_headers_almost_done) {
  STRICT_CHECK(ch != LF);

  if (parser->flags & F_TRAILING) {
    /* End of a chunked request */
    UPDATE_STATE(NEW_MESSAGE());
    CALLBACK_NOTIFY(message_complete);
    SKIP_ONE();
  }

  UPDATE_STATE(s_headers_done);

  /* Set this here so that on_headers_complete() callbacks can see it */
  parser->upgrade =
    (parser->flags & F_UPGRADE || parser->method == HTTP_CONNECT);

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
    switch (settings->on_headers_complete(parser)) {
      case 0:
        break;

      case 1:
        parser->flags |= F_SKIPBODY;
        break;

      default:
        RETURN_ERROR(HPE_CB_headers_complete);
    }
  }

  if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
    FINISH(p);
  }

  REEXECUTE();
}

STATE(s_headers_done) {
  STRICT_CHECK(ch != LF);

  parser->nread = 0;

  /* Exit, the rest of the connect is in a different protocol. */
  if (parser->upgrade) {
    UPDATE_STATE(NEW_MESSAGE());
    CALLBACK_NOTIFY(message_complete);
    FINISH(p + 1);
  }

  if (parser->flags & F_SKIPBODY) {
    UPDATE_STATE(NEW_MESSAGE());
    CALLBACK_NOTIFY(message_complete);
  } else if (parser->flags & F_CHUNKED) {
    /* chunked encoding - ignore Content-Length header */
    UPDATE_STATE(s_chunk_size_start);
  } else {
    if (parser->content_length == 0) {
      /* Content-Length header given but zero: Content-Length: 0\r\n */
      UPDATE_STATE(NEW_MESSAGE());
      CALLBACK_NOTIFY(message_complete);
    } else if (parser->content_length != ULLONG_MAX) {
      /* Content-Length header given and non-zero */
      SET_PARSING_DATA();
      UPDATE_STATE(s_body_identity);
    } else {
      if (parser->type == HTTP_REQUEST ||
          !http_message_needs_eof(parser)) {
        /* Assume content-length 0 - read the next */
        UPDATE_STATE(NEW_MESSAGE());
        CALLBACK_NOTIFY(message_complete);
      } else {
        /* Read body until EOF */
        SET_PARSING_DATA();
        UPDATE_STATE(s_body_identity_eof);
      }
    }
  }

  SKIP_ONE();
}

STATE(s_body_identity) {
  uint64_t to_read = MIN(parser->content_length, (uint64_t) (end - p));

  assert(parser->content_length != 0
      && parser->content_length != ULLONG_MAX);

  /* The difference between advancing content_length and p is because
   * the latter will automaticaly advance on the next loop iteration.
   * Further, if content_length ends up at 0, we want to see the last
   * byte again for our message complete callback.
   */
  SET_MARK(body);
  parser->content_length -= to_read;
  p += to_read - 1;

  if (parser->content_length == 0) {
    UPDATE_STATE(s_message_done);

    /* Mimic CALLBACK_DATA_NOADVANCE() but with one extra byte.
     *
     * The alternative to doing this is to wait for the next byte to
     * trigger the data callback, just as in every other case. The
     * problem with this is that this makes it difficult for the test
     * harness to distinguish between complete-on-EOF and
     * complete-on-length. It's not clear that this distinction is
     * important for applications, but let's keep it for now.
     */
    CALLBACK_DATA_(body, p - MARK(body) + 1, p);
    REEXECUTE();
  }

  SKIP_ONE();
}

/* read until EOF */
STATE(s_body_identity_eof) {
  SET_MARK(body);
  p = end - 1;

  SKIP_ONE();
}

STATE(s_message_done) {
  CLEAR_PARSING_DATA();
  UPDATE_STATE(NEW_MESSAGE());
  CALLBACK_NOTIFY(message_complete);
  SKIP_ONE();
}

STATE(s_chunk_size_start) {
  int8_t unhex_val;

  assert(parser->nread == 1);
  assert(parser->flags & F_CHUNKED);

  unhex_val = unhex[(unsigned char)ch];
  if (UNLIKELY(unhex_val == -1)) {
    RETURN_ERROR(HPE_INVALID_CHUNK_SIZE);
  }

  parser->content_length = unhex_val;
  UPDATE_STATE(s_chunk_size);
  SKIP_ONE();
}

STATE(s_chunk_size) {
  uint64_t t;
  int8_t unhex_val;

  assert(parser->flags & F_CHUNKED);

  if (ch == CR) {
    UPDATE_STATE(s_chunk_size_almost_done);
    SKIP_ONE();
  }

  unhex_val = unhex[(unsigned char)ch];

  if (unhex_val == -1) {
    if (ch == ';' || ch == ' ') {
      UPDATE_STATE(s_chunk_parameters);
      SKIP_ONE();
    }

    RETURN_ERROR(HPE_INVALID_CHUNK_SIZE);
  }

  t = parser->content_length;
  t *= 16;
  t += unhex_val;

  /* Overflow? Test against a conservative limit for simplicity. */
  if (UNLIKELY((ULLONG_MAX - 16) / 16 < parser->content_length)) {
    RETURN_ERROR(HPE_INVALID_CONTENT_LENGTH);
  }

  parser->content_length = t;
  SKIP_ONE();
}

STATE(s_chunk_parameters) {
  assert(parser->flags & F_CHUNKED);
  /* just ignore this shit. TODO check for overflow */
  if (ch == CR) {
    UPDATE_STATE(s_chunk_size_almost_done);
  }
  SKIP_ONE();
}

STATE(s_chunk_size_almost_done) {
  assert(parser->flags & F_CHUNKED);
  STRICT_CHECK(ch != LF);

  parser->nread = 0;

  if (parser->content_length == 0) {
    parser->flags |= F_TRAILING;
    UPDATE_STATE(s_header_field_start);
  } else {
    SET_PARSING_DATA();
    UPDATE_STATE(s_chunk_data);
  }
  SKIP_ONE();
}

STATE(s_chunk_data) {
  uint64_t to_read = MIN(parser->content_length, (uint64_t) (end - p));

  assert(parser->flags & F_CHUNKED);
  assert(parser->content_length != 0
      && parser->content_length != ULLONG_MAX);

  /* See the explanation in s_body_identity for why the content
   * length and data pointers are managed this way.
   */
  SET_MARK(body);
  parser->content_length -= to_read;
  p += to_read - 1;

  if (parser->content_length == 0) {
    UPDATE_STATE(s_chunk_data_almost_done);
  }

  SKIP_ONE();
}

STATE(s_chunk_data_almost_done) {
  assert(parser->flags & F_CHUNKED);
  assert(parser->content_length == 0);
  STRICT_CHECK(ch != CR);
  UPDATE_STATE(s_chunk_data_done);
  CALLBACK_DATA(body);
  SKIP_ONE();
}

STATE(s_chunk_data_done) {
  assert(parser->flags & F_CHUNKED);
  STRICT_CHECK(ch != LF);
  parser->nread = 0;
  CLEAR_PARSING_DATA();
  UPDATE_STATE(s_chunk_size_start);
  SKIP_ONE();
}


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
state_cb parse_url_char(state_cb s, const char ch)
{
  if (ch == ' ' || ch == '\r' || ch == '\n') {
    return s_dead;
  }

#if HTTP_PARSER_STRICT
  if (ch == '\t' || ch == '\f') {
    return s_dead;
  }
#endif

  if (s == s_req_spaces_before_url) {
    /* Proxied requests are followed by scheme of an absolute URI (alpha).
     * All methods except CONNECT are followed by '/' or '*'.
     */

    if (ch == '/' || ch == '*') {
      return s_req_path;
    }

    if (IS_ALPHA(ch)) {
      return s_req_schema;
    }

  } else if (s == s_req_schema) {
    if (IS_ALPHA(ch)) {
      return s;
    }

    if (ch == ':') {
      return s_req_schema_slash;
    }
  } else if (s == s_req_schema_slash) {
    if (ch == '/') {
      return s_req_schema_slash_slash;
    }

  } else if (s == s_req_schema_slash_slash) {
    if (ch == '/') {
      return s_req_server_start;
    }

  } else if (s == s_req_server_with_at ||
             s == s_req_server_start ||
             s == s_req_server) {
    if (s == s_req_server_with_at && ch == '@') {
      return s_dead;
    }

    /* FALLTHROUGH */
    if (ch == '/') {
      return s_req_path;
    }

    if (ch == '?') {
      return s_req_query_string_start;
    }

    if (ch == '@') {
      return s_req_server_with_at;
    }

    if (IS_USERINFO_CHAR(ch) || ch == '[' || ch == ']') {
      return s_req_server;
    }
  } else if (s == s_req_path) {
    if (IS_URL_CHAR(ch)) {
      return s;
    }

    switch (ch) {
      case '?':
        return s_req_query_string_start;

      case '#':
        return s_req_fragment_start;
    }

  } else if (s == s_req_query_string_start || s == s_req_query_string) {
    if (IS_URL_CHAR(ch)) {
      return s_req_query_string;
    }

    switch (ch) {
      case '?':
        /* allow extra '?' in query string */
        return s_req_query_string;

      case '#':
        return s_req_fragment_start;
    }

  } else if (s == s_req_fragment_start) {
    if (IS_URL_CHAR(ch)) {
      return s_req_fragment;
    }

    switch (ch) {
      case '?':
        return s_req_fragment;

      case '#':
        return s;
    }

  } else if (s == s_req_fragment) {
    if (IS_URL_CHAR(ch)) {
      return s;
    }

    switch (ch) {
      case '?':
      case '#':
        return s;
    }
  }

  /* We should never fall out of the switch above unless there's an error */
  return s_dead;
}

static struct state_ret http_parser_execute_s(
    http_parser* parser,
    const http_parser_settings* settings,
    const char* data,
    size_t len) {
  const char* p = data;
  const char* end = data + len;
  const char* marks[max_mark];
  MARK(header_field) = 0;
  MARK(header_value) = 0;
  MARK(value) = 0;
  MARK(url) = 0;
  MARK(body) = 0;
  MARK(status) = 0;
  state_cb p_state = parser->state;
  int8_t err = parser->parsing_data << 2;
  int8_t* n_err = &err;

  if (len == 0) {
    if (CURRENT_STATE() == s_body_identity_eof) {
      /* Use of CALLBACK_NOTIFY() here would erroneously return 1 byte read if
       * we got paused.
       */
      CALLBACK_NOTIFY_NOADVANCE(message_complete);
      RETURN(data, 0);
    }

    if (CURRENT_STATE() == s_dead ||
        CURRENT_STATE() == s_start_req_or_res ||
        CURRENT_STATE() == s_start_res ||
        CURRENT_STATE() == s_start_req) {
      RETURN(data, 0);
    }

    SET_ERRNO(HPE_INVALID_EOF_STATE);
    RETURN(data + 1, 0);
  }


  if (CURRENT_STATE() == s_header_field)
    MARK(header_field) = data;
  if (CURRENT_STATE() == s_header_value)
    MARK(header_value) = data;
  if (CURRENT_STATE() == s_req_path ||
      CURRENT_STATE() == s_req_schema ||
      CURRENT_STATE() == s_req_schema_slash ||
      CURRENT_STATE() == s_req_schema_slash_slash ||
      CURRENT_STATE() == s_req_server_start ||
      CURRENT_STATE() == s_req_server ||
      CURRENT_STATE() == s_req_server_with_at ||
      CURRENT_STATE() == s_req_query_string_start ||
      CURRENT_STATE() == s_req_query_string ||
      CURRENT_STATE() == s_req_fragment_start ||
      CURRENT_STATE() == s_req_fragment) {
    MARK(url) = data;
  }

  if (CURRENT_STATE() == s_res_status) {
    MARK(status) = data;
  }

  p = data;
  while (p != end) {
    char ch;
    struct state_ret sret;

    ch = *p;

    if (LIKELY((err & 0x4) == 0)) {
      if (!COUNT_HEADER_SIZE(1)) {
        SET_ERRNO(HPE_HEADER_OVERFLOW);
        goto error;
      }
    }

    sret = CALL_STATE(CURRENT_STATE());
    p = sret.result;
    p_state = (state_cb) sret.state;

    if (LIKELY((err & 0x3) == 0))
      continue;

    parser->parsing_data = err >> 2;
    parser->state = p_state;
    if ((err & 0x3) == 2)
      goto error;
    RETURN(p, 0);
  }
  parser->parsing_data = err >> 2;

  /* Run callbacks for any marks that we have leftover after we ran our of
   * bytes. There should be at most one of these set, so it's OK to invoke
   * them in series (unset marks will not result in callbacks).
   *
   * We use the NOADVANCE() variety of callbacks here because 'p' has already
   * overflowed 'data' and this allows us to correct for the off-by-one that
   * we'd otherwise have (since CALLBACK_DATA() is meant to be run with a 'p'
   * value that's in-bounds).
   */

  assert(((MARK(header_field) ? 1 : 0) +
          (MARK(header_value) ? 1 : 0) +
          (MARK(url) ? 1 : 0)  +
          (MARK(body) ? 1 : 0) +
          (MARK(status) ? 1 : 0)) <= 1);

  CALLBACK_DATA_NOADVANCE(header_field);
  CALLBACK_DATA_NOADVANCE(header_value);
  CALLBACK_DATA_NOADVANCE(url);
  CALLBACK_DATA_NOADVANCE(body);
  CALLBACK_DATA_NOADVANCE(status);

  parser->state = p_state;
  RETURN(end, 0);

error:
  if (HTTP_PARSER_ERRNO(parser) == HPE_OK) {
    SET_ERRNO(HPE_UNKNOWN);
  }

  RETURN(p, 0);
}

size_t http_parser_execute (http_parser *parser,
                            const http_parser_settings *settings,
                            const char *data,
                            size_t len)
{
  /* We're in an error state. Don't bother doing anything. */
  if (HTTP_PARSER_ERRNO(parser) != HPE_OK) {
    return 0;
  }

  return http_parser_execute_s(parser, settings, data, len).result - data;
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
  void *data = parser->data; /* preserve application data */
  memset(parser, 0, sizeof(*parser));
  parser->data = data;
  parser->type = t;
  parser->state = (t == HTTP_REQUEST ? s_start_req : (t == HTTP_RESPONSE ? s_start_res : s_start_req_or_res));
  parser->http_errno = HPE_OK;
  parser->parsing_data = 0;
}

const char *
http_errno_name(enum http_errno err) {
  assert(err < (sizeof(http_strerror_tab)/sizeof(http_strerror_tab[0])));
  return http_strerror_tab[err].name;
}

const char *
http_errno_description(enum http_errno err) {
  assert(err < (sizeof(http_strerror_tab)/sizeof(http_strerror_tab[0])));
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
    case s_http_host_port_start:
    case s_http_userinfo:
    case s_http_userinfo_start:
      return 1;
    default:
      break;
  }

  return 0;
}

int
http_parser_parse_url(const char *buf, size_t buflen, int is_connect,
                      struct http_parser_url *u)
{
  state_cb s;
  const char *p;
  enum http_parser_url_fields uf, old_uf;
  int found_at = 0;

  u->port = u->field_set = 0;
  s = is_connect ? s_req_server_start : s_req_spaces_before_url;
  old_uf = UF_MAX;

  for (p = buf; p < buf + buflen; p++) {
    s = parse_url_char(s, *p);

    /* Figure out the next field that we're operating on */
    if (s == s_dead) {
      return 1;

    /* Skip delimeters */
    } else if (s == s_req_schema_slash ||
        s == s_req_schema_slash_slash ||
        s == s_req_server_start ||
        s == s_req_query_string_start ||
        s == s_req_fragment_start) {
      continue;
    } else if (s == s_req_schema) {
      uf = UF_SCHEMA;
    } else if (s == s_req_server_with_at ||
               s == s_req_server) {
      if (s == s_req_server_with_at)
        found_at = 1;

      /* FALLTROUGH */
      uf = UF_HOST;
    } else if (s == s_req_path) {
      uf = UF_PATH;
    } else if (s == s_req_query_string) {
      uf = UF_QUERY;
    } else if (s == s_req_fragment) {
      uf = UF_FRAGMENT;
    } else {
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
  if ((u->field_set & ((1 << UF_SCHEMA) | (1 << UF_HOST))) != 0) {
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
