#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <pthread.h>
#include <linux/types.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "../include/blacklist_types.h"

#define JSON_FILENAME "../blacklist_config.json"

#define THREE_TUPLES "/sys/fs/bpf/xdp/globals/three_tuples"
#define IP_PAIRS "/sys/fs/bpf/xdp/globals/ip_pairs"
#define SOURCE_IPS "/sys/fs/bpf/xdp/globals/source_ips"
#define DESTINATION_IPS "/sys/fs/bpf/xdp/globals/destination_ips"
#define DESTINATION_PORTS "/sys/fs/bpf/xdp/globals/dst_ports"
#define INTERFACES "/sys/fs/bpf/xdp/globals/interfaces"

#define MAPS 6

json_t *root = NULL;

void *parse_three_tuple(void *arg)
{
    int state;
    int tt_fd = bpf_obj_get(THREE_TUPLES);
    if (tt_fd < 0)
    {
        printf("Failed to open three_tuples ebpf map\n");
    }

    json_t *array = (json_t *)arg;
    size_t index;
    json_t *value;

    json_array_foreach(array, index, value)
    {
        const char *source_ip_str = json_string_value(json_object_get(value, "source_ip"));
        const char *destination_ip_str = json_string_value(json_object_get(value, "destination_ip"));
        int destination_port_int = json_integer_value(json_object_get(value, "destination_port"));
        int allow = json_integer_value(json_object_get(value, "allow"));

        struct three_tuple tuple;

        if (inet_pton(AF_INET, source_ip_str, &tuple.source_ip) != 1)
        {
            fprintf(stderr, "Invalid source IP: %s\n", source_ip_str);
            continue;
        }

        if (inet_pton(AF_INET, destination_ip_str, &tuple.destination_ip) != 1)
        {
            fprintf(stderr, "Invalid destination IP: %s\n", destination_ip_str);
            continue;
        }

        tuple.destination_port = htons(destination_port_int);

        printf("[three_tuple] src_ip=%d dst_ip=%d port=%d allow=%d\n",
               tuple.source_ip, tuple.destination_ip, tuple.destination_port, allow);

        state = bpf_map_update_elem(tt_fd, &tuple, &allow, BPF_ANY);

        if (state < 0)
        {
            printf("Failed to update three_tuples ebpf map\n");
        }
    }
}

void *parse_ip_to_ip(void *arg)
{
    int state;
    int pair_fd = bpf_obj_get(IP_PAIRS);
    if (pair_fd < 0)
    {
        printf("Failed to open ip_pairs ebpf map\n");
    }

    json_t *array = (json_t *)arg;
    size_t index;
    json_t *value;

    json_array_foreach(array, index, value)
    {
        const char *source_ip_str = json_string_value(json_object_get(value, "source_ip"));
        const char *destination_ip_str = json_string_value(json_object_get(value, "destination_ip"));
        int allow = json_integer_value(json_object_get(value, "allow"));

        struct ip_pair pair;

        if (inet_pton(AF_INET, source_ip_str, &pair.source_ip) != 1 ||
            inet_pton(AF_INET, destination_ip_str, &pair.destination_ip) != 1) {
            fprintf(stderr, "Invalid IP in ip_to_ip rule\n");
            continue;
        }

        printf("[ip_to_ip] src_ip=%d dst_ip=%d allow=%d\n",
               pair.source_ip, pair.destination_ip, allow);

        state = bpf_map_update_elem(pair_fd, &pair, &allow, BPF_ANY);

        if (state < 0)
        {
            printf("Failed to update ip_pairs ebpf map\n");
        }
    }
}

void *parse_ip_to_any(void *arg)
{
    int state;
    int source_fd = bpf_obj_get(SOURCE_IPS);
    if (source_fd < 0)
    {
        printf("Failed to open SOURCE_IPS BPF map\n");
    }

    json_t *array = (json_t *)arg;
    size_t index;
    json_t *value;

    json_array_foreach(array, index, value)
    {
        const char *source_ip_str = json_string_value(json_object_get(value, "source_ip"));
        int allow = json_integer_value(json_object_get(value, "allow"));

        __be32 source_ip;

        if (inet_pton(AF_INET, source_ip_str, &source_ip) != 1)
        {
            fprintf(stderr, "Invalid source IP in ip_to_any\n");
            continue;
        }

        printf("[ip_to_any] src_ip=%d allow=%d\n", source_ip, allow);

        state = bpf_map_update_elem(source_fd, &source_ip, &allow, BPF_ANY);

        if (state < 0)
        {
            printf("Failed to update source_ips ebpf map\n");
        }
    }
}

void *parse_any_to_ip(void *arg)
{
    int state;
    int destination_fd = bpf_obj_get(DESTINATION_IPS);
    if (destination_fd < 0)
    {
        printf("Failed to open destination_ips ebpf map\n");
    }

    json_t *array = (json_t *)arg;
    size_t index;
    json_t *value;

    json_array_foreach(array, index, value)
    {
        const char *destination_ip_str = json_string_value(json_object_get(value, "destination_ip"));
        int allow = json_integer_value(json_object_get(value, "allow"));

        __be32 destination_ip;

        if (inet_pton(AF_INET, destination_ip_str, &destination_ip) != 1)
        {
            fprintf(stderr, "Invalid destination IP in any_to_ip\n");
            continue;
        }

        printf("[any_to_ip] dst_ip=%d allow=%d\n", destination_ip, allow);

        state = bpf_map_update_elem(destination_fd, &destination_ip, &allow, BPF_ANY);

        if (state < 0)
        {
            printf("Failed to update destination_ips ebpf map\n");
        }
    }
}

void *parse_ports(void *arg)
{
    int state;
    int ports_fd = bpf_obj_get(DESTINATION_PORTS);
    if (ports_fd < 0)
    {
        printf("Failed to open dst_ports ebpf map\n");
    }

    json_t *array = (json_t *)arg;
    size_t index;
    json_t *value;

    json_array_foreach(array, index, value)
    {
        int destination_ports_int = json_integer_value(json_object_get(value, "destination_ports"));
        int allow = json_integer_value(json_object_get(value, "allow"));

        __be16 destination_port = htons(destination_ports_int);

        printf("[ports] name=%d allow=%d\n", destination_ports_int, allow);

        state = bpf_map_update_elem(ports_fd, &destination_port, &allow, BPF_ANY);

        if (state < 0)
        {
            printf("Failed to update dst_ports ebpf map\n");
        }
    }
}

void *parse_interface(void *arg)
{
    int state;
    int interface_fd = bpf_obj_get(INTERFACES);
    if (interface_fd < 0)
    {
        printf("Failed to open interfaces ebpf map\n");
    }

    json_t *array = (json_t *)arg;
    size_t index;
    json_t *value;

    json_array_foreach(array, index, value)
    {
        const char *interface_name = json_string_value(json_object_get(value, "interface_name"));
        int allow = json_integer_value(json_object_get(value, "allow"));

        printf("[interface] name=%s allow=%d\n", interface_name, allow);

        state = bpf_map_update_elem(interface_fd, &interface_name, &allow, BPF_ANY);

        if (state < 0)
        {
            printf("Failed to update interfaces ebpf map\n");
        }
    }
}

int get_map_fds(const char **maps, int *fds)
{
    for (int i = 0; i < MAPS; i++)
    {
        fds[i] = bpf_obj_get(maps[i]);
        if (fds[i] == -1)
        {
            printf("Failed to open BPF map %s\n", maps[i]);
            return 1;
       }
    }
    return 0;
}

int main(void)
{
    /*
    const char *maps[MAPS] =
    {
        THREE_TUPLES,
        IP_PAIRS,
        SOURCE_IPS,
        DESTINATION_IPS,
        DESTINATION_PORTS,
        INTERFACES,
    };

    int fds[MAPS] = {0};
    int state;

    state = get_map_fds(maps, fds);

    if (state)
    {
        printf("Program failed!");
        return state;
    }
    else
    {
        for (int i = 0; i < MAPS; i++)
        {
            printf("fd=%d\n", fds[i]);
        }
    }
    */

    json_error_t error;
    root = json_load_file(JSON_FILENAME, 0, &error);

    if (!root)
    {
        fprintf(stderr, "Error parsing JSON from %s: %s\n", JSON_FILENAME, error.text);
        return 1;
    }

    pthread_t thread1, thread2, thread3, thread4, thread5, thread6;

    pthread_create(&thread1, NULL, parse_three_tuple, (void *)json_object_get(root, "three_tuple"));
    pthread_create(&thread2, NULL, parse_ip_to_ip, (void *)json_object_get(root, "ip_to_ip"));
    pthread_create(&thread3, NULL, parse_any_to_ip, (void *)json_object_get(root, "any_to_ip"));
    pthread_create(&thread4, NULL, parse_ip_to_any, (void *)json_object_get(root, "ip_to_any"));
    pthread_create(&thread5, NULL, parse_interface, (void *)json_object_get(root, "interface"));
    pthread_create(&thread6, NULL, parse_ports, (void *)json_object_get(root, "ports"));

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    pthread_join(thread4, NULL);
    pthread_join(thread5, NULL);
    pthread_join(thread6, NULL);

    json_decref(root);
    return 0;
}
