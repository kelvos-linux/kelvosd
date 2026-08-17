#include "config.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

static void trim(char *s)
{
    char *start = s;
    char *end;

    while (*start && isspace((unsigned char)*start))
        start++;

    if (start != s)
        memmove(s, start, strlen(start) + 1);

    end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1)))
        *--end = '\0';
}

static int parse_bool(const char *value)
{
    if (!value)
        return -1;
    if (strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0)
        return 1;
    if (strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0)
        return 0;
    return -1;
}

static void unquote(char *s)
{
    size_t len = strlen(s);
    if (len >= 2 && ((s[0] == '"' && s[len - 1] == '"') || (s[0] == '\'' && s[len - 1] == '\''))) {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }
}

int load_config(const char *path, struct config *cfg)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;

    memset(cfg, 0, sizeof(*cfg));
    cfg->enabled = 0;
    strncpy(cfg->log_file, "/var/log/kelvos_traffic_monitor.jsonl", CONFIG_LOG_PATH_MAX - 1);

    char line[512];
    int in_traffic_table = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *eq;
        trim(line);
        if (line[0] == '\0' || line[0] == '#')
            continue;

        if (line[0] == '[') {
            char *end = strchr(line, ']');
            if (end) {
                size_t n = (size_t)(end - (line + 1));
                char tbl[128] = {0};
                if (n > 0 && n < sizeof(tbl)) {
                    memcpy(tbl, line + 1, n);
                    tbl[n] = '\0';
                    trim(tbl);
                    if (strcasecmp(tbl, "traffic_monitor") == 0)
                        in_traffic_table = 1;
                    else
                        in_traffic_table = 0;
                } else {
                    in_traffic_table = 0;
                }
            }
            continue;
        }

        if (!in_traffic_table)
            continue;

        eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;
        trim(key);
        trim(val);

        char *hash = strchr(val, '#');
        if (hash)
            *hash = '\0';
        trim(val);

        unquote(val);

        if (strcasecmp(key, "enabled") == 0) {
            int parsed = parse_bool(val);
            if (parsed >= 0)
                cfg->enabled = parsed;
        } else if (strcasecmp(key, "ethernet_interface") == 0 ||
                   strcasecmp(key, "interface") == 0) {
            strncpy(cfg->ethernet_interface, val, IF_NAMESIZE - 1);
            cfg->ethernet_interface[IF_NAMESIZE - 1] = '\0';
        } else if (strcasecmp(key, "traffic_log_file") == 0) {
            strncpy(cfg->log_file, val, CONFIG_LOG_PATH_MAX - 1);
            cfg->log_file[CONFIG_LOG_PATH_MAX - 1] = '\0';
        }
    }

    fclose(fp);
    return 0;
}
