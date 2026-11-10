# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: module loaded, nginx starts with empty http{}
--- config
    location = /t { return 204; }
--- request
GET /t
--- error_code: 204
