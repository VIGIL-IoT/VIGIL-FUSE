extern char *strcpy(char *, const char *);
#define COPY(a,b) strcpy(a,b)
void copy(char *out) { COPY(out, "macro"); }
