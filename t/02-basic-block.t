# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: POST then access => 403; DELETE then access => 200
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
    location / { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
    "DELETE /api/ip?ip=127.0.0.1\r\nHost: localhost\r\n\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 403, 200, 200]



=== TEST 2: blocklist off => always 200
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
    location / { blocklist off; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 200]



=== TEST 3: blocklist_status custom code
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
    location / { blocklist on; blocklist_status 429; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "GET /\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 429]



=== TEST 4: POST refresh returns 200 not 201
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
    "POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"ip\":\"127.0.0.1\"}\r\n",
]
--- error_code eval
[201, 200]



=== TEST 5: DELETE unknown IP => 404
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- request
DELETE /api/ip?ip=10.0.0.1
--- error_code: 404



=== TEST 6: malformed JSON body => 400 INVALID_BODY (Review Focus 1)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 9\r\n\r\n{not-json"
--- error_code: 400
--- response_body_like: INVALID_BODY



=== TEST 7: POST body over 4 KiB => 413 BODY_TOO_LARGE (Review Focus 2)
--- http_config
    blocklist_zone zone=bl:1m;
    client_max_body_size 1m;
--- config
    location /api/ { blocklist_api; }
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n" . ("x" x 5000)
--- error_code: 413
--- response_body_like: BODY_TOO_LARGE



=== TEST 8: DELETE without ?ip= => 400 MISSING_PARAM (Review Focus 4)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- request
DELETE /api/ip
--- error_code: 400
--- response_body_like: MISSING_PARAM
