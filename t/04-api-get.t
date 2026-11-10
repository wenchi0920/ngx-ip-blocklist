# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: GET /list returns all entries as JSON array
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"1.2.3.4\"}\r\n",
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"5.6.7.8\"}\r\n",
    "GET /api/list\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 201, 200]
--- response_body_like eval
['', '', '"ip":"1.2.3.4".*"ip":"5.6.7.8"|"ip":"5.6.7.8".*"ip":"1.2.3.4"']



=== TEST 2: GET /list?q=<existing-ip> => one entry
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"1.2.3.4\"}\r\n",
    "GET /api/list?q=1.2.3.4\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"1.2.3.4"']



=== TEST 3: GET /list?q=<unknown> => 404
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request
GET /api/list?q=9.9.9.9
--- error_code: 404



=== TEST 4: GET /list?q=<invalid> => 400 INVALID_IP
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request
GET /api/list?q=not-an-ip
--- error_code: 400
--- response_body_like: INVALID_IP



=== TEST 5: GET /list on empty table => 200 with empty array
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request
GET /api/list
--- error_code: 200
--- response_body_like eval
qr/"data":\s*\[\s*\]/



=== TEST 6: URL-encoded IPv6 colons decoded (Review Focus 4)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 22\r\n\r\n{\"ip\":\"2001:db8::1\"}\r\n",
    "GET /api/list?q=2001%3Adb8%3A%3A1\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"2001:db8::1"']
