#include <stdint.h>
void huskarl_browser_start(void *window, int32_t ephemeral);
int32_t huskarl_browser_poll(void);
void huskarl_browser_cancel(void);
void huskarl_browser_drop(void);
