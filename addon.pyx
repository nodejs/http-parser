from libc.stdlib cimport malloc, free
from libc.string cimport strlen
from cpython cimport bool, PyBytes_FromStringAndSize, PyBytes_FromString
cimport http_parser
import collections
import six

try:
    import urllib.parse as urlparse
except ImportError:
    import urlparse

def to_bytes(data):
    if isinstance(data, bytes):
        pass
    elif isinstance(data, unicode):
        data = data.encode('utf8')
    elif isinstance(data, (list, bytearray)):
        data = bytes(data)
    else:
        raise Exception('Can not coerce type: {} into bytes.'.format(type(data)))
    return data

cdef int on_message_begin(http_parser.http_parser *parser) except -1:
    cdef object parser_data = <object> parser.data
    parser_data.delegate.on_message_begin()
    return 0

cdef int on_url(http_parser.http_parser *parser, char *data, size_t length) except -1:
    cdef object parser_data = <object> parser.data
    cdef object url = PyBytes_FromStringAndSize(data, length)
    parser_data.delegate.on_url(url)
    return 0

cdef int on_status(http_parser.http_parser *parser, char *data, size_t length) except -1:
    cdef object parser_data = <object> parser.data
    cdef object status = PyBytes_FromStringAndSize(data, length)
    # data.delegate.on_status(parser.status_code)
    parser_data.delegate.on_status(status)
    return 0

cdef int on_header_field(http_parser.http_parser *parser, char *data, size_t length) except -1:
    cdef object parser_data = <object> parser.data
    cdef object header_field = PyBytes_FromStringAndSize(data, length)
    # data.delegate.on_header_field(parser.header_field_code)
    parser_data.delegate.on_header_field(header_field)
    return 0

cdef int on_header_value(http_parser.http_parser *parser, char *data, size_t length) except -1:
    cdef object parser_data = <object> parser.data
    cdef object header_value = PyBytes_FromStringAndSize(data, length)
    # data.delegate.on_header_value(parser.header_value_code)
    parser_data.delegate.on_header_value(header_value)
    return 0

cdef int on_headers_complete(http_parser.http_parser *parser) except -1:
    cdef object parser_data = <object> parser.data
    parser_data.delegate.on_headers_complete()
    return 0

cdef int on_body(http_parser.http_parser *parser, char *data, size_t length) except -1:
    cdef object parser_data = <object> parser.data
    cdef object body = PyBytes_FromStringAndSize(data, length)
    parser_data.delegate.on_body(
            body,
            length,
            # http_transfer_encoding_chunked(parser),
            False,
    )
    return 0

cdef int on_message_complete(http_parser.http_parser *parser) except -1:
    cdef object parser_data = <object> parser.data
    parser_data.delegate.on_message_complete(
            # http_transfer_encoding_chunked(parser),
            False,
            http_parser.http_should_keep_alive(parser))
    return 0

cdef int on_chunk_header(http_parser.http_parser *parser) except -1:
    cdef object parser_data = <object> parser.data
    parser_data.delegate.on_chunk_header()
    return 0

cdef int on_chunk_complete(http_parser.http_parser *parser) except -1:
    cdef object parser_data = <object> parser.data
    parser_data.delegate.on_chunk_complete()
    return 0

from vkproxy.utils import trace_calls


class ParserDelegate(object):
    def on_message_begin(self):
        pass

    def on_header_field(self, field):
        pass

    def on_header_value(self, value):
        pass

    def on_headers_complete(self):
        pass

    def on_body(self, data, length, is_chunked):
        pass

    def on_message_complete(self, is_chunked, should_keep_alive):
        pass

    def on_chunk_header(self):
        pass

    def on_chunk_complete(self):
        pass


@trace_calls()
class RequestParserDelegate(ParserDelegate):
    def on_url(self, url):
        pass


@trace_calls()
class ResponseParserDelegate(ParserDelegate):
    def on_status(self, status):
        pass


cdef class ParserData(object):
    cdef public object delegate

    def __cinit__(self, object delegate):
        self.delegate = delegate

cdef class HttpEventParser(object):
    cdef http_parser.http_parser *_parser
    cdef http_parser.http_parser_settings _settings
    cdef object data

    def __cinit__(self, object delegate, http_parser.http_parser_type parser_type):
        # init parser
        self._parser = <http_parser.http_parser *> malloc(sizeof(http_parser.http_parser))
        http_parser.http_parser_init(self._parser, parser_type)

        self.data = ParserData(delegate)
        self._parser.data = <void *> self.data

        # set callbacks
        self._settings.on_message_begin = <http_cb> on_message_begin
        self._settings.on_url = <http_data_cb> on_url
        self._settings.on_status = <http_data_cb> on_status
        self._settings.on_header_field = <http_data_cb> on_header_field
        self._settings.on_header_value = <http_data_cb> on_header_value
        self._settings.on_headers_complete = <http_cb> on_headers_complete
        self._settings.on_body = <http_data_cb> on_body
        self._settings.on_message_complete = <http_cb> on_message_complete
        self._settings.on_chunk_header = <http_cb> on_chunk_header
        self._settings.on_chunk_complete = <http_cb> on_chunk_complete

    def destroy(self):
        if self._parser != NULL:
            free(self._parser)
            self._parser = NULL

    def __dealloc__(self):
        self.destroy()

    def execute(self, data):
        data = to_bytes(data)
        self._execute(data, len(data))

    cdef int _execute(self, char *data, size_t length):
        cdef int nparsed
        cdef http_parser.http_errno errno

        if self._parser == NULL:
            raise Exception('Parser destroyed or not initialized!')

        nparsed = http_parser.http_parser_execute(self._parser, &self._settings, data, length)

        if nparsed != length:
            errno = http_parser.HTTP_PARSER_ERRNO(self._parser)
            name = http_parser.http_errno_name(errno)
            desc = http_parser.http_errno_description(errno)
            raise Exception('Parser gave error {errno}/{name}: {desc}'.format(errno=errno, name=name, desc=desc))

        return 0


class ParseResult(collections.namedtuple('ParseResult',
                                         ['scheme', 'hostname', 'port', 'raw_path', 'query', 'fragment', 'userinfo'])):
    __slots__ = ()

    @property
    def netloc(self):
        ret = []
        if self.userinfo:
            ret.append(self.userinfo)
            ret.append(b'@')
        if self.hostname:
            ret.append(self.hostname)
        if self.port:
            ret.append(b':')
            if six.PY3:
                ret.append(bytes(str(self.port), 'ascii'))
            else:
                ret.append(str(self.port))
        return b''.join(ret)

    @property
    def path(self):
        return self.raw_path.split(b';', 1)[0]

    @property
    def params(self):
        if b';' in self.raw_path:
            return self.raw_path.split(b';', 1)
        else:
            return b''

    @property
    def username(self):
        if not self.userinfo:
            return
        return self.userinfo.split(b':', 1)[0]

    @property
    def password(self):
        if not self.userinfo:
            return
        return self.userinfo.split(b':', 1)[1]

    def as_strings(self):
        if six.PY3:
            args = [i == 2 and str(x) or x.decode() for i, x in enumerate(self)]
        else:
            args = self
        return self.__class__(*args)

    def _as_urlparse_result_tuple(self):
        ret = [self.scheme, self.netloc, self.path, self.params, self.query, self.fragment]
        if six.PY3:
            ret = [x.decode() for x in ret]
        return ret

    def as_urlparse_result(self):
        return urlparse.ParseResult(*self._as_urlparse_result_tuple())

    def geturl(self):
        return urlparse.urlunparse(self._as_urlparse_result_tuple())


cdef class HttpUrlParser(object):
    cdef http_parser.http_parser_url *_parser
    cdef object data

    def __cinit__(self):
        # init parser
        self._parser = <http_parser.http_parser_url *> malloc(sizeof(http_parser.http_parser_url))
        http_parser.http_parser_url_init(self._parser)

    def destroy(self):
        if self._parser != NULL:
            free(self._parser)
            self._parser = NULL

    def __dealloc__(self):
        self.destroy()

    def parse(self, url, is_connect):
        url = to_bytes(url)
        ret = self._parse(url, len(url), is_connect)
        return ParseResult(*ret)

    cdef object _parse(self, char *url, size_t length, bool is_connect):
        cdef int rv
        cdef object ret

        if self._parser == NULL:
            raise Exception('Parser destroyed or not initialized!')

        rv = http_parser.http_parser_parse_url(url, length, is_connect, self._parser)
        if rv != 0:
            raise Exception('URL Parser gave error: {rv}'.format(rv=rv))

        ret = []
        for i in range(http_parser.UF_MAX):
            if i == http_parser.UF_PORT:
                # This is so it's an integer as expected
                if self._parser.port:
                    ret.append(self._parser.port)
                else:
                    # Match urlparse
                    ret.append(None)
            elif self._parser.field_set & (1 << i) == 0:
                ret.append('')
            else:
                f_off = self._parser.field_data[i].off
                f_len = self._parser.field_data[i].len
                part = url[f_off:f_off + f_len]
                ret.append(part)

        return ret

def RequestParser(parser_delegate):
    return HttpEventParser(parser_delegate, http_parser.HTTP_REQUEST)

def ResponseParser(parser_delegate):
    return HttpEventParser(parser_delegate, http_parser.HTTP_RESPONSE)
