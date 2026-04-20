#include <linux/bpf.h>
#include <linux/if_ether.h>   // ethhdr, ETH_P_IP
#include <linux/ip.h>          // iphdr
#include <bpf/bpf_helpers.h>   // SEC, bpf_printk
#include <arpa/inet.h>         // bpf_ntohs (or use __builtin_bswap16)
#include <bpf/bpf_endian.h>    // bpf_ntohs

// Return the protocol of this packet
// 1 = ICMP
// 6 = TCP
// 17 = UDP

// copy data pointer
// copy data end pointer
// create ethernet header data structure with everything starting at data pointer
// if wrong size return 0
// flip big to little endian and check if the payload is an IPv4 type packet
// create ipheader data structure starting from data+ the size of the ethernet header


unsigned char lookup_protocol(struct xdp_md *ctx) {
    unsigned char protocol = 0;
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
        return 0;
    // Check that it's an IP packet
    if (bpf_ntohs(eth->h_proto) == ETH_P_IP)
    {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
        }
    return protocol;
    }

SEC("xdp")
int ping(struct xdp_md *ctx) {
    long protocol = lookup_protocol(ctx);
    if (protocol == 1) // ICMP
    {
    bpf_printk("Hello ping");
    }
    return XDP_PASS;
}