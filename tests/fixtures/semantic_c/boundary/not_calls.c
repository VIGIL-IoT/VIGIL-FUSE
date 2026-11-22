/* strcpy(out, input); esp_ota_begin(0, 0, 0); */
void contains_strcpy_name(void) {}
#if 0
void dead(void) { strcpy(out, input); }
#endif
void safe_wrapper(char *out) { out[0]=0; }
void use(char *out) { safe_wrapper(out); }
