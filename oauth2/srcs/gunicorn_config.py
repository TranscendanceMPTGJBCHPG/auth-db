bind = "0.0.0.0:8080"
workers = 3
timeout = 3600
certfile = '/etc/ssl/nginx.crt'
keyfile = '/etc/ssl/nginx.key'
do_handshake_on_connect = True
ssl_ciphers = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256'
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}
ssl_minimum_version = 'TLSv1_2'
forwarded_allow_ips = '*'
proxy_allow_ips = '*'
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190