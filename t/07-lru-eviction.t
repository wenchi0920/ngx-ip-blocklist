# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

repeat_each(1);

run_tests();

__DATA__

=== TEST 1: oversubscribe tiny zone => earliest insert evicted
# Insert 500 IPs 10.0.X.Y into a zone sized for far fewer than 500 entries.
# After the storm, verify the earliest inserted IP (10.0.0.1) has been evicted
# while one of the latest (10.0.1.243, inserted around position 497/500) is
# still resident. Exact capacity is implementation-dependent; the test only
# asserts "some evictions happened and LRU order is honoured".
--- http_config
    blocklist_zone zone=bl:32k;
--- config
    location /api/ { blocklist_api; blocklist_api_token "t"; }
--- pipelined_requests eval
[
    (map {
        my $o3   = int($_ / 254);
        my $o4   = ($_ % 254) + 1;
        my $body = "{\"ip\":\"10.0.$o3.$o4\"}";
        "POST /api/ip\r\nHost: localhost\r\nAuthorization: Bearer t\r\n"
            . "Content-Type: application/json\r\n"
            . "Content-Length: " . length($body) . "\r\n\r\n"
            . $body
    } 0..499),
    "GET /api/list?q=10.0.0.1\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
    "GET /api/list?q=10.0.1.243\r\nHost: localhost\r\nAuthorization: Bearer t\r\n\r\n",
]
--- error_code eval
[(201) x 500, 404, 200]
