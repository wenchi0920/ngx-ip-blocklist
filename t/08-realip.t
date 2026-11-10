# vim:set ft= ts=4 sw=4 et fdm=marker:
#
# Nginx must be built with --with-http_realip_module (standard in Debian
# and most distro builds).

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: XFF ip is what gets blocked
# Operator trusts 127.0.0.0/8 and tells realip to read X-Forwarded-For.
# We POST 9.9.9.9 as the blocked IP, then issue two requests with
# different XFF values; only the one whose XFF matches gets 403.
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    set_real_ip_from 127.0.0.0/8;
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location = /t { blocklist on; return 200; }
--- pipelined_requests eval
[
    "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{\"ip\":\"9.9.9.9\"}",
    "GET /t\r\nHost: localhost\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n",
    "GET /t\r\nHost: localhost\r\nX-Forwarded-For: 1.2.3.4\r\n\r\n",
]
--- error_code eval
[201, 403, 200]
