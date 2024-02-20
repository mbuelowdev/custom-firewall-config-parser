# firewall-config-parser

Small, dirty, generic xml to csv parser for some custom xml format.

### Webserver/PHP Config

/etc/nginx/nginx.conf somewhere under "http"
```nginx
client_max_body_size 100M;
```

/etc/php/7.4/fpm/php.ini
```nginx
post_max_size = 100M
upload_max_filesize = 100M
```