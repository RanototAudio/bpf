#!/usr/bin/env python3
from bcc import BPF
import time
import sys

# bpf program
program = r"""
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

int modify_packet(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // ethernet header
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;

    // ipv4 filter
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // ip header
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void*)(iph + 1) > data_end)
        return XDP_PASS;

    // udp filter
    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    // udp header
    struct udphdr *udp = (void*)iph + sizeof(struct iphdr);
    if ((void*)(udp + 1) > data_end)
        return XDP_PASS;

    // payload start
    unsigned char *payload = (unsigned char *)udp + sizeof(struct udphdr);
    
    // bounds check
    if ((void*)(payload + 5) > data_end)
        return XDP_PASS;

    // modify hello to bye
    if (payload[0] == 'h' && payload[1] == 'e' && payload[2] == 'l' && 
        payload[3] == 'l' && payload[4] == 'o') {
        
        payload[0] = 'b';
        payload[1] = 'y';
        payload[2] = 'e';
        payload[3] = ' ';
        payload[4] = ' ';
        
        bpf_trace_printk("Modified hello to bye\\n");
    }

    return XDP_PASS;
}
"""

device = "lo"
if len(sys.argv) > 1:
    device = sys.argv[1]

flags = 0 

b = None
try:
    b = BPF(text=program)
    fn = b.load_func("modify_packet", BPF.XDP)
    b.attach_xdp(device, fn, flags)

    while True:
        time.sleep(1)
except KeyboardInterrupt:
    pass
finally:
    if b:
        b.remove_xdp(device, flags)
