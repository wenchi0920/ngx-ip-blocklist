# vim:set ft= ts=4 sw=4 et fdm=marker:

use Test::Nginx::Socket 'no_plan';

run_tests();

__DATA__

=== TEST 1: missing Authorization => 401
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401



=== TEST 2: wrong token => 401
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: Bearer wrong
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401



=== TEST 3: correct token => endpoint reached (404 for unknown IP)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: Bearer s3cret
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 404



=== TEST 4: wrong-length token => 401 (Review Focus 5, guards against early-exit on length mismatch)
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: Bearer s3cret_longer_than_configured
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401



=== TEST 5: malformed Authorization (no "Bearer ") => 401
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; blocklist_api_token "s3cret"; }
--- more_headers
Authorization: s3cret
--- request
DELETE /api/ip?ip=1.2.3.4
--- error_code: 401



=== TEST 6: blocklist_api without token => nginx fails to start
--- http_config
    blocklist_zone zone=bl:1m;
--- config
    location /api/ { blocklist_api; }
--- must_die
--- error_log
blocklist_api_token
