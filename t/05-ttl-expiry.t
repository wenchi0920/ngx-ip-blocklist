# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: POST with ttl:2 => blocks immediately
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location = /t { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"ip\":\"127.0.0.1\",\"ttl\":2}",
    "GET /t\r\nHost: localhost\r\n\r\n",
]
--- error_code eval
[201, 403]



=== TEST 2: after expiry, request passes
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location = /t { blocklist on; return 200; }
--- request eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 26\r\n\r\n{\"ip\":\"127.0.0.1\",\"ttl\":1}",
    "GET /t",
]
--- wait: 2
--- error_code eval
[201, 200]



=== TEST 3: no ttl => permanent (short sleep still blocked)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location = /t { blocklist on; return 200; }
--- request eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 18\r\n\r\n{\"ip\":\"127.0.0.1\"}",
    "GET /t",
]
--- wait: 2
--- error_code eval
[201, 403]



=== TEST 4: negative ttl => 400 INVALID_TTL
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer t\r\nContent-Length: 25\r\n\r\n{\"ip\":\"1.2.3.4\",\"ttl\":-1}"
--- error_code: 400
--- response_body_like: INVALID_TTL



=== TEST 5: non-integer ttl => 400 INVALID_TTL
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request eval
"POST /api/ip\r\nHost: localhost\r\nContent-Type: application/json\r\nAuthorization: Bearer t\r\nContent-Length: 28\r\n\r\n{\"ip\":\"1.2.3.4\",\"ttl\":\"abc\"}"
--- error_code: 400
--- response_body_like: INVALID_TTL
