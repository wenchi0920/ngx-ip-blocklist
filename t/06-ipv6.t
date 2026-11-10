# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: IPv6 POST compressed => stored, GET /list returns same form
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"2001:db8::1\"}",
    "GET /api/list\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"2001:db8::1"']



=== TEST 2: IPv6 uppercase input normalised (Review Focus 3)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"2001:DB8::1\"}",
    "GET /api/list?q=2001:db8::1\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]



=== TEST 3: IPv4-mapped literal "::ffff:1.2.3.4" treated as 1.2.3.4
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 23\r\n\r\n{\"ip\":\"::ffff:1.2.3.4\"}",
    "GET /api/list?q=1.2.3.4\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
--- response_body_like eval
['', '"ip":"1.2.3.4"']



=== TEST 4: IPv6 with zone id => 400 INVALID_IP (Review Focus 3)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer t\r\nContent-Length: 21\r\n\r\n{\"ip\":\"fe80::1%eth0\"}"
--- error_code: 400
--- response_body_like: INVALID_IP



=== TEST 5: block an IPv6 client via listen [::1]:...
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    listen [::1]:$TEST_NGINX_SERVER_PORT;
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location / { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"ip\":\"::1\"}",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 403]
