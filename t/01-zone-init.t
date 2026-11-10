# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: nginx starts with blocklist_zone
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location = /t { return 204; }
--- request
GET /t
--- error_code: 204

=== TEST 2: missing zone size is a config error
--- http_config
    blocklist_zone zone=bl;
--- config
    location = /t { return 204; }
--- must_die
--- error_log
invalid

=== TEST 3: two blocklist_zone directives rejected
--- http_config
    blocklist_zone zone=a:1m;
    blocklist_zone zone=b:1m;
--- config
    location = /t { return 204; }
--- must_die
--- error_log
duplicate
