extern void *memcpy(void *, const void *, unsigned long);
extern void *memmove(void *, const void *, unsigned long);
extern char *strcat(char *, const char *);
extern int sprintf(char *, const char *, ...);
extern int vsprintf(char *, const char *, __builtin_va_list);
extern char *gets(char *);
extern int scanf(const char *, ...);
typedef struct _IO_FILE FILE;
extern int fscanf(FILE *, const char *, ...);
extern int sscanf(const char *, const char *, ...);
void calls(char *out, const char *in, __builtin_va_list args) { memcpy(out,in,4); memmove(out,in,4); strcat(out,in); sprintf(out,"%s",in); vsprintf(out,"%s",args); gets(out); sscanf(in,"%s",out); scanf("%3s",out); fscanf((void *)0,"%s",out); }
