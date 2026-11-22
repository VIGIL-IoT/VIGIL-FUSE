extern void mbedtls_ssl_conf_authmode(void *, int);
void connect(void *config) { mbedtls_ssl_conf_authmode(config, 2); }
