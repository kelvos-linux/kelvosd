#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <jansson.h>

// The event struct as defined in BPF
struct traffic_event {
    __u32 timestamp_ns;
    __u32 ifindex;
    __u16 eth_proto;
    __u8  ip_version;
    __u8  ip_ttl;
    __u16 ip_tot_len;
    __u32 ip_saddr;
    __u32 ip_daddr;
    __u8  transport_proto;
    __u16 sport;
    __u16 dport;
    __u8  tcp_flags;
    __u32 tcp_seq;
    __u32 tcp_ack;
    __u16 tcp_window;
    __u16 payload_len;
};

static volatile sig_atomic_t exit_flag = 0;
static FILE *log_file = NULL;
static int perf_fd = -1;
static struct bpf_link *xdp_link = NULL;
static struct bpf_object *obj = NULL;

static void handle_signal(int sig) {
    (void)sig;
    exit_flag = 1;
}

// Convert flags bitmask to JSON object (for TCP flags)
static json_t *tcp_flags_to_json(__u8 flags) {
    json_t *f = json_object();
    json_object_set_new(f, "syn", json_boolean(flags & 0x01));
    json_object_set_new(f, "ack", json_boolean(flags & 0x02));
    json_object_set_new(f, "fin", json_boolean(flags & 0x04));
    json_object_set_new(f, "rst", json_boolean(flags & 0x08));
    json_object_set_new(f, "psh", json_boolean(flags & 0x10));
    json_object_set_new(f, "urg", json_boolean(flags & 0x20));
    return f;
}

// Handle a single event from perf buffer
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    (void)ctx; (void)cpu;
    if (data_sz < sizeof(struct traffic_event))
        return;

    struct traffic_event *ev = (struct traffic_event *)data;

    // Build JSON root
    json_t *root = json_object();

    // Timestamp (convert ns to ISO 8601)
    time_t sec = ev->timestamp_ns / 1000000000ULL;
    long nsec = ev->timestamp_ns % 1000000000ULL;
    struct tm tm;
    gmtime_r(&sec, &tm);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);
    char ts_full[80];
    snprintf(ts_full, sizeof(ts_full), "%s.%09ldZ", ts, nsec);
    json_object_set_new(root, "timestamp", json_string(ts_full));

    // Interface name
    char ifname[IF_NAMESIZE];
    if (if_indextoname(ev->ifindex, ifname))
        json_object_set_new(root, "interface", json_string(ifname));
    else
        json_object_set_new(root, "interface", json_integer(ev->ifindex));

    json_object_set_new(root, "direction", json_string("ingress"));

    // Ethernet
    json_t *eth = json_object();
    // We don't have MAC addresses from XDP (costly), so we set placeholders
    json_object_set_new(eth, "destination_mac", json_string("00:00:00:00:00:00"));
    json_object_set_new(eth, "source_mac", json_string("00:00:00:00:00:00"));
    char eth_type[8];
    snprintf(eth_type, sizeof(eth_type), "0x%04x", ev->eth_proto);
    json_object_set_new(eth, "ethertype", json_string(eth_type));
    json_t *vlan = json_object();
    json_object_set_new(vlan, "enabled", json_false());
    json_object_set_new(vlan, "id", json_null());
    json_object_set_new(vlan, "priority", json_null());
    json_object_set_new(eth, "vlan", vlan);
    json_object_set_new(root, "ethernet", eth);

    // Network (IPv4 only in this example)
    json_t *net = json_object();
    if (ev->ip_version == 4) {
        json_object_set_new(net, "protocol", json_string("IPv4"));
        json_object_set_new(net, "version", json_integer(4));
        json_object_set_new(net, "header_length", json_integer(20)); // assume no options
        json_object_set_new(net, "total_length", json_integer(ev->ip_tot_len));
        json_object_set_new(net, "identification", json_integer(0)); // not captured
        json_t *flags = json_object();
        json_object_set_new(flags, "df", json_false());
        json_object_set_new(flags, "mf", json_false());
        json_object_set_new(net, "flags", flags);
        json_object_set_new(net, "fragment_offset", json_integer(0));
        json_object_set_new(net, "ttl", json_integer(ev->ip_ttl));
        json_object_set_new(net, "protocol_number", json_integer(ev->transport_proto));
        json_object_set_new(net, "checksum", json_string("0x0000")); // not captured
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ev->ip_saddr, src, sizeof(src));
        inet_ntop(AF_INET, &ev->ip_daddr, dst, sizeof(dst));
        json_object_set_new(net, "source_ip", json_string(src));
        json_object_set_new(net, "destination_ip", json_string(dst));
    } else {
        json_object_set_new(net, "protocol", json_string("Non-IP"));
    }
    json_object_set_new(root, "network", net);

    // Transport
    json_t *trans = json_object();
    if (ev->transport_proto == IPPROTO_TCP) {
        json_object_set_new(trans, "protocol", json_string("TCP"));
        json_object_set_new(trans, "source_port", json_integer(ev->sport));
        json_object_set_new(trans, "destination_port", json_integer(ev->dport));
        json_object_set_new(trans, "sequence_number", json_integer(ev->tcp_seq));
        json_object_set_new(trans, "acknowledgement_number", json_integer(ev->tcp_ack));
        json_object_set_new(trans, "header_length", json_integer(20)); // simplified
        json_object_set_new(trans, "flags", tcp_flags_to_json(ev->tcp_flags));
        json_object_set_new(trans, "window_size", json_integer(ev->tcp_window));
        json_object_set_new(trans, "checksum", json_string("0x0000"));
        json_object_set_new(trans, "urgent_pointer", json_integer(0));
        json_object_set_new(trans, "options", json_array()); // empty for now
    } else if (ev->transport_proto == IPPROTO_UDP) {
        json_object_set_new(trans, "protocol", json_string("UDP"));
        json_object_set_new(trans, "source_port", json_integer(ev->sport));
        json_object_set_new(trans, "destination_port", json_integer(ev->dport));
        json_object_set_new(trans, "length", json_integer(ev->ip_tot_len - 20 - 8)); // approximate
        json_object_set_new(trans, "checksum", json_string("0x0000"));
    } else {
        json_object_set_new(trans, "protocol", json_string("Other"));
    }
    json_object_set_new(root, "transport", trans);

    // Application (placeholder – could be enhanced with deeper inspection)
    json_t *app = json_object();
    json_object_set_new(app, "protocol", json_string("Unknown"));
    json_object_set_new(app, "server_name", json_null());
    json_object_set_new(app, "alpn", json_null());
    json_object_set_new(app, "http", json_null());
    json_object_set_new(app, "dns", json_null());
    json_object_set_new(root, "application", app);

    // Payload (just length, no data capture to keep perf)
    json_t *payload = json_object();
    json_object_set_new(payload, "length", json_integer(ev->payload_len));
    json_object_set_new(payload, "encoding", json_string("none"));
    json_object_set_new(payload, "data", json_string(""));
    json_object_set_new(root, "payload", payload);

    // Flow (simple hashing could be added; placeholder)
    json_t *flow = json_object();
    json_object_set_new(flow, "flow_id", json_string("unset"));
    json_object_set_new(flow, "stream_id", json_integer(0));
    json_object_set_new(flow, "session_id", json_string("unset"));
    json_object_set_new(root, "flow", flow);

    // Metadata
    json_t *meta = json_object();
    json_object_set_new(meta, "capture_method", json_string("XDP"));
    json_object_set_new(meta, "kernel_timestamp", json_true());
    json_object_set_new(meta, "rss_queue", json_integer(0));
    json_object_set_new(meta, "cpu", json_integer(cpu));
    json_object_set_new(meta, "process", json_null());
    json_object_set_new(meta, "user", json_null());
    json_object_set_new(root, "metadata", meta);

    // Write JSON to log file
    char *json_str = json_dumps(root, JSON_COMPACT);
    if (json_str) {
        fprintf(log_file, "%s\n", json_str);
        fflush(log_file);
        free(json_str);
    }
    json_decref(root);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <config-file>\n", argv[0]);
        return 1;
    }

    // Read config
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen config");
        return 1;
    }

    char line[256];
    char ifname[IF_NAMESIZE] = {0};
    char log_path[512] = "/var/log/kelvos_traffic_monitor.log";
    int enabled = 0;

    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TRAFFICE_MONITOR_ENABLED=", 25) == 0) {
            char *val = line + 25;
            val[strcspn(val, "\r\n")] = '\0';
            if (strcmp(val, "true") == 0) enabled = 1;
        } else if (strncmp(line, "TRAFFICE_MONITOR_ETHERNET_INTERFACE=", 36) == 0) {
            strncpy(ifname, line + 36, sizeof(ifname) - 1);
            ifname[strcspn(ifname, "\r\n")] = '\0';
        } else if (strncmp(line, "TRAFFICE_MONITOR_LOG_FILE=", 26) == 0) {
            strncpy(log_path, line + 26, sizeof(log_path) - 1);
            log_path[strcspn(log_path, "\r\n")] = '\0';
        }
    }
    fclose(fp);

    if (!enabled) {
        printf("Traffic monitor is disabled.\n");
        return 0;
    }
    if (ifname[0] == '\0') {
        fprintf(stderr, "Interface not specified in config.\n");
        return 1;
    }

    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    // Open log file (append)
    log_file = fopen(log_path, "a");
    if (!log_file) {
        perror("fopen log");
        return 1;
    }
    setlinebuf(log_file); // line buffered

    printf("Interface: %s (index %d), logging to %s\n", ifname, ifindex, log_path);

    // Load and attach XDP program
    obj = bpf_object__open_file("xdp_prog.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        goto cleanup;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_monitor");
    if (!prog) {
        fprintf(stderr, "Failed to find XDP program 'xdp_monitor'\n");
        goto cleanup;
    }

    xdp_link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(xdp_link)) {
        fprintf(stderr, "Failed to attach XDP program\n");
        xdp_link = NULL;
        goto cleanup;
    }

    // Get the perf event map
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "traffic_events");
    if (!map) {
        fprintf(stderr, "Failed to find perf map 'traffic_events'\n");
        goto cleanup;
    }
    int map_fd = bpf_map__fd(map);

    // Setup perf buffer
    struct perf_buffer *pb = perf_buffer__new(map_fd, 8, handle_event, NULL, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    // Signal handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("Monitoring traffic. Press Ctrl+C to stop.\n");

    // Poll for events
    while (!exit_flag) {
        perf_buffer__poll(pb, 100);
    }

    perf_buffer__free(pb);

cleanup:
    if (xdp_link) bpf_link__destroy(xdp_link);
    if (obj) bpf_object__close(obj);
    if (log_file) fclose(log_file);
    printf("Exiting.\n");
    return 0;
}