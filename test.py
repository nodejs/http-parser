#!/usr/bin/env python


# import pyximport
# pyximport.install(
#     inplace=True,
#     # reload_support=True,
# )


from vkproxy.log import get_logger
_LOG = get_logger()

import pyrox.http.parser as parser

class ParserDelegate(parser.ParserDelegate):
    def on_message_begin(self):
        print(self, 'on_message_begin')
        pass

    def on_req_method(self, method):
        print(self, 'on_req_method', method)
        pass

    def on_req_url(self, url):
        print(self, 'on_req_url', url)
        pass

    def on_resp_status(self, code, desc):
        print(self, 'on_resp_status', code, desc)
        pass

    def on_header_field(self, field):
        print(self, 'on_header_field', field)
        pass

    def on_header_value(self, value):
        print(self, 'on_header_value', value)
        pass

    def on_http_version(self, major, minor):
        print(self, 'on_http_version', major, minor)
        pass

    def on_headers_complete(self, keep_alive):
        print(self, 'on_headers_complete', keep_alive)
        pass

    def on_body(self, data, length, is_chunked):
        print(self, 'on_body', data, length, is_chunked)
        pass

    def on_message_complete(self, is_chunked, keep_alive):
        print(self, 'on_message_complete', is_chunked, keep_alive)
        pass

    def on_chunk_header(self):
        print(self, 'on_chunk_header')
        pass

    def on_chunk_complete(self):
        print(self, 'on_chunk_complete')
        pass

    def on_upgrade(self):
        print(self, 'on_upgrade')
        pass



UNEXPECTED_HEADER_REQUEST = (
    'GET /test/12345?field=f1&field2=f2#fragment HTTP/1.1\r\n'
    'Test: test\r\n'
    'Connection: keep-alive\r\n'
    'Content-Length: 12\r\n\r\n'
    'This is test'
)

NORMAL_REQUEST = (
    'GET /test/12345?field=f1&field2=f2#fragment HTTP/1.1\r\n'
    'Connection: keep-alive\r\n'
    'Content-Length: 12\r\n\r\n'
    'This is test'
)

CHUNKED_REQUEST = (
    'GET /test/12345?field=f1&field2=f2#fragment HTTP/1.1\r\n'
    'Connection: keep-alive\r\n'
    'Transfer-Encoding: chunked\r\n\r\n'
    '1e\r\nall your base are belong to us\r\n'
    '0\r\n'
    '\r\n'
)

requests = [UNEXPECTED_HEADER_REQUEST, NORMAL_REQUEST, CHUNKED_REQUEST]

_LOG.info('+++++')
_LOG.info('Request prep')
req_delegate = ParserDelegate()
req_parser = parser.RequestParser(req_delegate)

for request in requests:
    _LOG.info('-----')
    _LOG.info('request: %s', request)
    print(req_parser.execute(request))

NORMAL_RESPONSE = """HTTP/1.1 200 OK\r
Content-Length: 12\r\n\r
This is test"""

CHUNKED_RESPONSE = """HTTP/1.1 200 OK\r
Transfer-Encoding: chunked\r\n\r
1e\r\nall your base are belong to us\r
0\r
"""

responses = [NORMAL_RESPONSE, CHUNKED_RESPONSE]

_LOG.info('Response prep')
resp_delegate = ParserDelegate()
resp_parser = parser.ResponseParser(resp_delegate)

for response in responses:
    _LOG.info('-----')
    _LOG.info('response: %s', response)
    print(resp_parser.execute(response))


urlp = parser.HttpUrlParser()
p = urlp.parse('http://192.168.99.100', False)
print(p)
p = urlp.parse('192.168.99.100:443', True)
print(p)

url = 'http://trevorj:test@192.168.99.100:8080/omg?yes=true&nope=whoa#anchorbaby'
p = urlp.parse(url, False)
print(p)

