#include <stdint.h>
// All calls occur on the main thread. Actions: restore=0, login=1, GET=2, logout=3.
// Completion runs on the main thread: 2=success, 3=failure. It must remain
// callable until completion, including when shutdown is deferred.
typedef void (*HuskarlCompletion)(int32_t result);
void huskarl_native_start(void *window, int32_t action, int32_t ephemeral, HuskarlCompletion completion);
void huskarl_native_cancel(void);
void huskarl_native_shutdown(HuskarlCompletion completion);
// Valid until the next bridge call; copy immediately. Contains no credentials.
const char *huskarl_native_status(void);
// Credential-free UI state. Read on the main thread after completion.
// Phase: 0=unconfigured, 1=signed out, 2=ready, 3=cleanup required,
// 4=restore required, 5=transition in progress.
// Persistence: 0=unknown, 1=absent, 2=saved, 3=unsaved changes.
typedef struct { int32_t phase; int32_t persistence; } HuskarlSessionState;
HuskarlSessionState huskarl_native_state(void);
