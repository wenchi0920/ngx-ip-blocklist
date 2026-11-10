# vim:set ft= ts=4 sw=4 et fdm=marker:
#
# Spray a mix of POST and GET across several workers. Verify that every
# request gets a response (so no crash, no hang) and the response is one of
# the sensible values for its method. The point is to shake the slab mutex
# under concurrent writers and readers, not to pin exact cache contents.

use Test::Nginx::Socket 'no_plan';

repeat_each(1);

run_tests();

__DATA__

=== TEST 1: multi-worker mixed POST + GET, no crash
--- main_config
    worker_processes 4;
--- http_config
    blocklist_zone zone=bl:4m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
    location = /t { blocklist on; return 200; }
--- pipelined_requests eval
[
    (map {
        if ($_ % 2 == 0) {
            my $o4   = ($_ % 254) + 1;
            my $body = "{\"ip\":\"10.1.1.$o4\"}";
            "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\n"
                . "Content-Type: application/json\r\n"
                . "Content-Length: " . length($body) . "\r\n\r\n"
                . $body
        } else {
            "GET /t\r\nHost: localhost\r\n\r\n"
        }
    } 0..399),
]
--- error_code eval
# Even indices: POST → 201 (new) or 200 (refresh). Odd indices: GET → 200
# (not blocked) or 403 (blocked at the moment it ran). The oracle accepts
# both outcomes for each slot; what we are really asserting is that every
# request came back with ONE of the acceptable codes — no empty slots, no
# crashes, no hangs.
[
    map { $_ % 2 == 0 ? qr/^(201|200)$/ : qr/^(200|403)$/ } 0..399
]
--- timeout: 30
