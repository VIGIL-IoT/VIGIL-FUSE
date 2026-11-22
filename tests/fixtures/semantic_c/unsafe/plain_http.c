extern void *esp_http_client_init(const void *);
void connect(void) { esp_http_client_init("http://example.invalid"); }
