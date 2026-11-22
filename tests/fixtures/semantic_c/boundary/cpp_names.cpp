extern "C" char *strcpy(char *, const char *);
namespace firmware { void copy(char *out) { ::strcpy(out,"cpp"); } }
namespace unrelated { void strcpy() {} }
void ordinary() { unrelated::strcpy(); }
