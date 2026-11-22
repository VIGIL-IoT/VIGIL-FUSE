/* Stand-in declarations exercise names, not SDK ABI compatibility. */
extern void esp_tls_conn_new(void);
extern void esp_tls_conn_http_new(void);
extern void esp_http_client_init(void);
extern void esp_mqtt_client_init(void);
extern void esp_https_ota(void);
extern void esp_ota_begin(void);
extern void esp_ota_end(void);
extern void esp_secure_boot_verify_signature(void);
extern void mbedtls_ssl_conf_authmode(void);
extern void mbedtls_ssl_set_hostname(void);
extern void mbedtls_ssl_get_verify_result(void);
extern void mbedtls_pk_parse_key(void);
extern void esp_console_init(void);
void observe(void) {
esp_tls_conn_new();
esp_tls_conn_http_new();
esp_http_client_init();
esp_mqtt_client_init();
esp_https_ota();
esp_ota_begin();
esp_ota_end();
esp_secure_boot_verify_signature();
mbedtls_ssl_conf_authmode();
mbedtls_ssl_set_hostname();
mbedtls_ssl_get_verify_result();
mbedtls_pk_parse_key();
esp_console_init();
}
