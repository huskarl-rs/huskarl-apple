#include <stdint.h>
// All calls occur on the main thread. Actions: restore=0, login=1, GET=2, logout=3.
void huskarl_native_start(void *window, int32_t action, int32_t ephemeral);
int32_t huskarl_native_poll(void);
void huskarl_native_cancel(void);
void huskarl_native_shutdown(void);
// Valid until the next bridge call; copy immediately. Contains no credentials.
const char *huskarl_native_status(void);
