/* Controlled analysis input. Never run on a target. Construction labels only. */
#ifndef SECURE
#define SECURE 0
#endif
#ifndef UNREFERENCED
#define UNREFERENCED 0
#endif

const char *volatile fuse_endpoint_sink;

__attribute__((noinline)) void record_endpoint(const char *value) {
    fuse_endpoint_sink = value;
}

#if UNREFERENCED
/* Retained data has no code reference; the unused function may be eliminated. */
__attribute__((used)) static const char unused_http[] = "http://unused.example:8080";
__attribute__((used)) static const char unused_mqtt[] = "mqtt://unused.example:1883";
static void eliminated(void) {
    record_endpoint("http://eliminated.example");
}
#endif

void _start(void) {
#if SECURE || UNREFERENCED
    record_endpoint("https://device.example/update");
    record_endpoint("mqtts://broker.example:8883");
#else
    record_endpoint("http://device.example:8080/update?token=sentinel-query-value");
    record_endpoint("mqtt://fixture-user:sentinel-password@192.0.2.1:1883/topic");
#endif
    for (;;) { }
}
