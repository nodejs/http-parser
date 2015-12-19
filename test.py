#!/usr/bin/env python

# import pyximport
# pyximport.install(
#     inplace=True,
#     # reload_support=True,
# )


from vkproxy.log import get_logger
_LOG = get_logger()

import hparser


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
)

requests = [UNEXPECTED_HEADER_REQUEST, NORMAL_REQUEST, CHUNKED_REQUEST]

_LOG.info('+++++')
_LOG.info('Request prep')
req_delegate = hparser.RequestParserDelegate()
req_parser = hparser.RequestParser(req_delegate)

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
resp_delegate = hparser.ResponseParserDelegate()
resp_parser = hparser.ResponseParser(resp_delegate)

for response in responses:
    _LOG.info('-----')
    _LOG.info('response: %s', response)
    print(resp_parser.execute(response))


urlp = hparser.HttpUrlParser()
p = urlp.parse('http://192.168.99.100', False)
print(p)
p = urlp.parse('192.168.99.100:443', True)
print(p)

url = 'http://trevorj:test@192.168.99.100:8080/omg?yes=true&nope=whoa#anchorbaby'
p = urlp.parse(url, False)
print(p)

