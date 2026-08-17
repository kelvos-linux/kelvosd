#ifndef CONFIG_H
#define CONFIG_H

#include <net/if.h>

#define CONFIG_LOG_PATH_MAX 512

struct config {
    int enabled;
    char ethernet_interface[IF_NAMESIZE];
    char log_file[CONFIG_LOG_PATH_MAX];
};

int load_config(const char *path, struct config *cfg);

#endif // CONFIG_H
