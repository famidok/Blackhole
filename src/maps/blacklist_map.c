#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <pthread.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/blacklist_types.h"

#define JSON_FILENAME "../blacklist_config.json"
#define THREE_TUPLES "/sys/fs/bpf/xdp/globals/three_tuples"
#define IP_PAIRS "/sys/fs/bpf/xdp/globals/ip_pairs"
#define SUBNETS "/sys/fs/bpf/xdp/globals/ipv4_lpm_map"
#define SOURCE_IPS "/sys/fs/bpf/xdp/globals/source_ips"
#define DESTINATION_IPS "/sys/fs/bpf/xdp/globals/destination_ips"
#define DESTINATION_PORTS "/sys/fs/bpf/xdp/globals/dst_ports"
#define INTERFACES "/sys/fs/bpf/xdp/globals/interfaces"
#define PROTOCOLS "/sys/fs/bpf/xdp/globals/protocols"

void *parset_subnet(void *arg) {
    int fd = bpf_obj_get(SUBNETS);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        struct ipv4_lpm_key lpm;
        const char *subnet_str = json_string_value(json_object_get(val, "subnet"));
        int a = json_integer_value(json_object_get(val, "allow"));
        char ip[16] = {0};
        int prefix = 0;
        sscanf(subnet_str, "%15[^/]/%d", ip, &prefix);
        inet_pton(AF_INET, ip, &lpm.ip);
        lpm.prefixlen = prefix;
        bpf_map_update_elem(fd, &lpm, &a, BPF_ANY);
    }

    return NULL;
}

void *parse_three_tuple(void *arg) {
    int fd = bpf_obj_get(THREE_TUPLES);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        struct three_tuple t;
        inet_pton(AF_INET, json_string_value(json_object_get(val, "source_ip")), &t.source_ip);
        inet_pton(AF_INET, json_string_value(json_object_get(val, "destination_ip")), &t.destination_ip);
        t.destination_port = htons(json_integer_value(json_object_get(val, "destination_port")));
        int a = json_integer_value(json_object_get(val, "allow"));
        bpf_map_update_elem(fd, &t, &a, BPF_ANY);
    }
    return NULL;
}

void *parse_ip_to_ip(void *arg) {
    int fd = bpf_obj_get(IP_PAIRS);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        struct ip_pair p;
        inet_pton(AF_INET, json_string_value(json_object_get(val, "source_ip")), &p.source_ip);
        inet_pton(AF_INET, json_string_value(json_object_get(val, "destination_ip")), &p.destination_ip);
        int a = json_integer_value(json_object_get(val, "allow"));
        bpf_map_update_elem(fd, &p, &a, BPF_ANY);
    }
    return NULL;
}

void *parse_ip_to_any(void *arg) {
    int fd = bpf_obj_get(SOURCE_IPS);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        __be32 ip;
        inet_pton(AF_INET, json_string_value(json_object_get(val, "source_ip")), &ip);
        int a = json_integer_value(json_object_get(val, "allow"));
        bpf_map_update_elem(fd, &ip, &a, BPF_ANY);
    }
    return NULL;
}

void *parse_any_to_ip(void *arg) {
    int fd = bpf_obj_get(DESTINATION_IPS);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        __be32 ip;
        inet_pton(AF_INET, json_string_value(json_object_get(val, "destination_ip")), &ip);
        int a = json_integer_value(json_object_get(val, "allow"));
        bpf_map_update_elem(fd, &ip, &a, BPF_ANY);
    }
    return NULL;
}

void *parse_ports(void *arg) {
    int fd = bpf_obj_get(DESTINATION_PORTS);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        __be16 p = htons(json_integer_value(json_object_get(val, "destination_port")));
        int a = json_integer_value(json_object_get(val, "allow"));
        bpf_map_update_elem(fd, &p, &a, BPF_ANY);
    }
    return NULL;
}

void *parse_interface(void *arg) {
    int fd = bpf_obj_get(INTERFACES);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        const char *n = json_string_value(json_object_get(val, "interface_name"));
        int a = json_integer_value(json_object_get(val, "allow"));
        bpf_map_update_elem(fd, n, &a, BPF_ANY);
    }
    return NULL;
}

void *parse_protocols(void *arg) {
    int fd = bpf_obj_get(PROTOCOLS);
    if (fd < 0 || !arg) return NULL;
    json_t *val; size_t i;
    json_array_foreach((json_t *)arg, i, val) {
        uint8_t p = (uint8_t)json_integer_value(json_object_get(val, "protocol"));
        uint8_t a = (uint8_t)json_integer_value(json_object_get(val, "allow"));
        bpf_map_update_elem(fd, &p, &a, BPF_ANY);
    }
    return NULL;
}

int main(void) {
    json_error_t err;
    json_t *root = json_load_file(JSON_FILENAME, 0, &err);
    if (!root) return 1;
    pthread_t t[8];

    pthread_create(&t[0], NULL, parse_three_tuple, json_object_get(root, "three_tuple"));
    pthread_create(&t[1], NULL, parse_ip_to_ip, json_object_get(root, "ip_to_ip"));
    pthread_create(&t[2], NULL, parse_any_to_ip, json_object_get(root, "any_to_ip"));
    pthread_create(&t[3], NULL, parse_ip_to_any, json_object_get(root, "ip_to_any"));
    pthread_create(&t[4], NULL, parse_interface, json_object_get(root, "interfaces"));
    pthread_create(&t[5], NULL, parse_ports, json_object_get(root, "ports"));
    pthread_create(&t[6], NULL, parse_protocols, json_object_get(root, "protocols"));
    pthread_create(&t[7], NULL, parset_subnet, json_object_get(root, "subnets"));

    for (int i = 0; i < 8; i++) pthread_join(t[i], NULL);
    json_decref(root);

    return 0;
}