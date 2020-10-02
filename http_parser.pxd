from libc.stdint cimport uint16_t, uint32_t, uint64_t
#from libc.string cimport const_char
#from smart_ptr cimport shared_ptr


cdef extern from "http_parser.h":
    cdef enum http_parser_type:
        HTTP_REQUEST, HTTP_RESPONSE, HTTP_BOTH

    cdef enum flags:
        F_CHUNKED = 1
        F_CONNECTION_KEEP_ALIVE = 2
        F_CONNECTION_CLOSE = 4
        F_CONNECTION_UPGRADE = 8
        F_TRAILING = 16
        F_UPGRADE = 32
        F_SKIPBODY = 64

    cdef enum http_parser_url_fields:
        UF_SCHEMA = 0
        UF_HOST = 1
        UF_PORT = 2
        UF_PATH = 3
        UF_QUERY = 4
        UF_FRAGMENT = 5
        UF_USERINFO = 6
        UF_MAX = 7

    ctypedef struct field_data:
        uint16_t off  # Offset into buffer in which field starts
        uint16_t len  # Length of run in buffer

    cdef struct http_parser_url:
        uint16_t field_set  # Bitmask of (1 << UF_*) values
        uint16_t port  # Converted UF_PORT string

        # 7 here is UF_MAX above
        field_data[7] field_data

    cdef unsigned long http_parser_version();

    cdef struct http_parser:
        # enum http_parser_type
        unsigned int type
        unsigned int flags
        # enum state
        unsigned int state
        # enum header_state
        unsigned int header_state
        # index into current matcher
        unsigned int index

        # number of bytes read in various scenarios
        uint32_t nread
        # bytes in body (0 if no Content-Length header)
        uint64_t content_length

        # READ-ONLY
        unsigned short http_major
        unsigned short http_minor
        unsigned int status_code  # Responses only
        unsigned int method  # Requests only
        unsigned int http_errno

        # 1 = Upgrade header was present and the parser has exited because of that.
        # 0 = No upgrade header present.
        # Should be checked when http_parser_execute() returns in addition to
        # error checking.
        unsigned int upgrade  #: 1

        # PUBLIC
        void *data  # A pointer to get hook to the "connection" or "socket" object

    ctypedef int (*http_data_cb)(http_parser*, const char *at, size_t length);
    ctypedef int (*http_cb)(http_parser*);

    cdef struct http_parser_settings:
        http_cb      on_message_begin
        http_data_cb on_url
        http_data_cb on_status
        http_data_cb on_header_field
        http_data_cb on_header_value
        http_cb      on_headers_complete
        http_data_cb on_body
        http_cb      on_message_complete
        # When on_chunk_header is called, the current chunk length is stored
        # in parser->content_length.
        http_cb      on_chunk_header
        http_cb      on_chunk_complete

    cdef enum http_errno:
        HPE_OK
        HPE_CB_message_begin
        HPE_CB_url
        HPE_CB_header_field
        HPE_CB_header_value
        HPE_CB_headers_complete
        HPE_CB_body
        HPE_CB_message_complete
        HPE_CB_status
        HPE_CB_chunk_header
        HPE_CB_chunk_complete
        HPE_INVALID_EOF_STATE
        HPE_HEADER_OVERFLOW
        HPE_CLOSED_CONNECTION
        HPE_INVALID_VERSION
        HPE_INVALID_STATUS
        HPE_INVALID_METHOD
        HPE_INVALID_URL
        HPE_INVALID_HOST
        HPE_INVALID_PORT
        HPE_INVALID_PATH
        HPE_INVALID_QUERY_STRING
        HPE_INVALID_FRAGMENT
        HPE_LF_EXPECTED
        HPE_INVALID_HEADER_TOKEN
        HPE_INVALID_CONTENT_LENGTH
        HPE_INVALID_CHUNK_SIZE
        HPE_INVALID_CONSTANT
        HPE_INVALID_INTERNAL_STATE
        HPE_STRICT
        HPE_PAUSED
        HPE_UNKNOWN

    cdef http_errno HTTP_PARSER_ERRNO(http_parser* p);  # wrap-ignore

    cdef enum http_method:
        HTTP_DELETE = 0
        HTTP_GET = 1
        HTTP_HEAD = 2
        HTTP_POST = 3
        HTTP_PUT = 4
        HTTP_CONNECT = 5
        HTTP_OPTIONS = 6
        HTTP_TRACE = 7
        HTTP_COPY = 8
        HTTP_LOCK = 9
        HTTP_MKCOL = 10
        HTTP_MOVE = 11
        HTTP_PROPFIND = 12
        HTTP_PROPPATCH = 13
        HTTP_SEARCH = 14
        HTTP_UNLOCK = 15
        HTTP_BIND = 16
        HTTP_REBIND = 17
        HTTP_UNBIND = 18
        HTTP_ACL = 19
        HTTP_REPORT = 20
        HTTP_MKACTIVITY = 21
        HTTP_CHECKOUT = 22
        HTTP_MERGE = 23
        HTTP_MSEARCH = 24
        HTTP_NOTIFY = 25
        HTTP_SUBSCRIBE = 26
        HTTP_UNSUBSCRIBE = 27
        HTTP_PATCH = 28
        HTTP_PURGE = 29
        HTTP_MKCALENDAR = 30
        HTTP_LINK = 31
        HTTP_UNLINK = 32


cdef extern from "http_parser.c":
    void http_parser_init(http_parser *parser, http_parser_type type);  # wrap-ignore
    size_t http_parser_execute(http_parser *parser,
                               const http_parser_settings *settings,
                               const char *data,
                               size_t len); # wrap-ignore
    int http_should_keep_alive(const http_parser *parser);  # wrap-ignore

    const char *http_method_str(http_method m);
    const char *http_errno_name(http_errno err);
    const char *http_errno_description(http_errno err);

    void http_parser_url_init(http_parser_url *u);  # wrap-ignore
    int http_parser_parse_url(const char *buf, size_t buflen,
                              int is_connect,
                              http_parser_url *u);  # wrap-ignore

    void http_parser_pause(http_parser *parser, int paused)  # wrap-ignore
    int http_body_is_final(const http_parser *parser)  # wrap-ignore


