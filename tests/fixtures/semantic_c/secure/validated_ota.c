extern int esp_secure_boot_verify_signature(const void *, unsigned);
extern int esp_ota_begin(int, unsigned, int *);
void update(const void *image, int *handle) { if (esp_secure_boot_verify_signature(image, 64)==0) esp_ota_begin(0, 64, handle); }
