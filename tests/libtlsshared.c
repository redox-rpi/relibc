// Thread-local data in a shared library that is loaded at start, so it
// lives in the static TLS block (tls_shared.c).
_Thread_local int lib_gd = 11;
__attribute__((tls_model("initial-exec"))) _Thread_local int lib_ie = 22;

int lib_get_gd(void) { return lib_gd; }
int lib_get_ie(void) { return lib_ie; }
int *lib_addr_gd(void) { return &lib_gd; }
int *lib_addr_ie(void) { return &lib_ie; }
