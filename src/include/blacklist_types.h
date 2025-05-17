#ifndef BLACKLIST_TYPES_H
#define BLACKLIST_TYPES_H

#include <linux/types.h>

struct ip_pair
{
    __be32 source_ip;
    __be32 destination_ip;
};

// Don't need structs for SIP, DIP, DPort, MAC (Interface)

__be32 source_ip = 0 ;
__be32 destination_ip = 0;
__be16 destination_port = 0 ;
// unsigned char interface[6] = {0};

struct three_tuple
{
    __be32 source_ip;
    __be32 destination_ip;
    __be16 destination_port;
};

struct interface_info
{
    unsigned char interface[6];
};

struct ipv4_lpm_key
{
    __u32 prefixlen;
    __u32 data;
};


#endif //BLACKLIST_TYPES_H