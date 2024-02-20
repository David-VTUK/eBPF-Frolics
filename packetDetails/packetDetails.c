
//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} rb SEC(".maps");

struct packetDetails
{
    unsigned int src_addr;
    unsigned int dst_addr;
    unsigned int protocol;

};

SEC("xdp")
int packet_details(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    struct iphdr *ip;

    struct packetDetails *packet;

    // Verify that the Ethernet packet contains an IP packet
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    // Move past the Ethernet header to get the IP header
    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Reserve space in the ring buffer
    packet = bpf_ringbuf_reserve(&rb,sizeof(packet), 0);
  
    if (!packet) {
        // Ideally, we'd handle not being able to
        // reserve space, for testing purposes we'll
        // simply allow it
        return XDP_PASS;
    }

    packet->src_addr = ip->saddr;
    packet->dst_addr = ip->daddr;
    packet->protocol = ip->protocol;

    bpf_ringbuf_submit(packet, 0);

    return XDP_PASS;

}


char LICENSE[] SEC("license") = "GPL";
