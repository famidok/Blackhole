#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <string.h>
#include "../include/blacklist_types.h"
#include "../include/blacklist_maps.h"

static int __always_inline check_and_drop(void *map, void *key)
{
    /*
	void *value = bpf_map_lookup_elem(map, key); // 1 or NULL
	if (value)
          return 1;
    else
    	return 0;
    */
    return bpf_map_lookup_elem(map, key) ? 1 : 0;
}

SEC("prog")
int blacklist(struct xdp_md *ctx)
{
    //void *value;
    struct three_tuple t_tuple;
    memset(&t_tuple, 0, sizeof(t_tuple));
    struct ip_pair pair;
    memset(&pair, 0, sizeof(pair));
    struct interface_info intf;
    memset(&intf, 0, sizeof(intf));

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
    {
        return XDP_PASS;
    }

    if (eth->h_proto != htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    memcpy(intf.interface, eth->h_source, ETH_ALEN);

    struct iphdr *iph = (struct iphdr *)(eth + 1);

    if ((void *)(iph + 1) > data_end)
    {
        return XDP_PASS;
    }

    t_tuple.source_ip = iph->saddr;
    t_tuple.destination_ip = iph->daddr;
    source_ip = iph->saddr;
    destination_ip = iph->daddr;

    if (iph->protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
        if ((void *)(tcph + 1) > data_end)
        {
            return XDP_DROP;
        }

        t_tuple.destination_port = tcph->dest;
        destination_port = tcph->dest;
    }
    else if (iph->protocol == IPPROTO_UDP)
    {
        struct udphdr *udph = (struct udphdr *)(iph + 1);
        if ((void *)(udph + 1) > data_end)
        {
            return XDP_DROP;
        }

        t_tuple.destination_port = udph->dest;
        destination_port = udph->dest;

    }
    else
    {
        return XDP_PASS;
    }

    pair.source_ip = iph->saddr;
    pair.destination_ip = iph->daddr;

    // Three Tuple Drop
    if (check_and_drop(&three_tuples, &t_tuple))
    {
        return XDP_DROP;
    }

    // SIP - DIP Drop
    if (check_and_drop(&ip_pairs, &pair))
    {
        return XDP_DROP;
    }

    // SIP DROP
    if (check_and_drop(&source_ips, &iph->saddr))
    {
        return XDP_DROP;
    }

    // DIP DROP
    if (check_and_drop(&destination_ips, &iph->daddr))
    {
        return XDP_DROP;
    }

    // DPort DROP
    if (check_and_drop(&destination_ports, &destination_port))
    {
        return XDP_DROP;
    }

    // Subnet DROP

    // Interface DROP
    if (check_and_drop(&interfaces, intf.interface))
    {
        return XDP_DROP;
    }

     return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
