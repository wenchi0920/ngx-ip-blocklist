# vim:set ft= ts=4 sw=4 et fdm=marker:
#
# Behavioural tests for the fixes applied after the final whole-branch
# code review:
#
#   - error-message prose distinct from machine-readable code
#   - dispatcher tolerates a location prefix without a trailing slash

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: error response has prose `error` distinct from machine `code`
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- more_headers
Authorization: Bearer t
--- request
DELETE /api/ip
--- error_code: 400
--- response_body_like eval
qr/"error":"required query parameter missing".*"code":"MISSING_PARAM"/



=== TEST 2: dispatcher accepts location without trailing slash
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"ip\":\"1.2.3.4\"}",
    "DELETE /api/ip?ip=1.2.3.4\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[201, 200]
