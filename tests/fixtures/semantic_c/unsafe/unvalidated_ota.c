extern int esp_ota_begin(int, unsigned, int *);
void update(int *handle) { esp_ota_begin(0, 64, handle); }
