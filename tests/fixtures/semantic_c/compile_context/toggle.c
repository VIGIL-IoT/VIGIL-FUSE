extern char *strcpy(char *, const char *);
void selected(char *out) {
#if ENABLE_COPY
strcpy(out, "enabled");
#else
out[0]=0;
#endif
}
