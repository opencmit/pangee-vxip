#ifndef __WARP_STRUCTS_H__
#define __WARP_STRUCTS_H__

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>
#include <linux/version.h>
#include <sys/socket.h>

#include <bpf_helpers.h>
#include <bpf_endian.h>

#define WARP_SET    1
#define WARP_UNSET  0

enum warp_action {
    WARP_ACT_OK = 0,
    WARP_ACT_PASS,
    WARP_ACT_DROP,
    WARP_ACT_REDIRECT,
    WARP_ACT_UNREACH,
    WARP_ACT_MAX,
};

#ifndef bool
#define bool _Bool
#endif

enum {
    false = 0,
    true  = 1,
};

struct warp_ip {
    __be32 addr;
};

struct warp_ipv6 {
    __be32 addr[4];
};

struct warp_sockaddr {
    __u8   af;
    __u8   l4_proto;
    __be16 port;
    union
    {
        struct warp_ip   addr4;
        struct warp_ipv6 addr6;
    };
};

struct warp_ipaddr {
    union
    {
        struct warp_ip   addr4;
        struct warp_ipv6 addr6;
    };
};

struct warp_fib_cache {
    unsigned char dmac[ETH_ALEN];
    unsigned char smac[ETH_ALEN];
};

struct warp_connection {
    struct warp_sockaddr saddr;
    struct warp_sockaddr daddr;
};

struct warp_redirect {
    struct warp_connection redirect;
    __s32                  redirect_if_idx;
    __u8                   is_local;
    __u8                   is_local_port;
    __u8                   positive;
    __u8                   reserve;
    __u64                  ts;
};

struct warp_context {
    bool                 is_ipv6;
    __u8                 l4_proto;
    __u8                 l3_header_len;
    __u32                l4_header_len;
    __u32                cpu;
    struct ethhdr       *l2h;
    void                *l3h;
    void                *l4h;
    void                *begin;
    void                *end; 
    struct warp_sockaddr org_saddr;
    struct warp_sockaddr org_daddr;
    struct warp_redirect forward;
    void                *stack_ctx;
};

struct warp_service {
    struct warp_sockaddr laddr;
    __u8                 strategy;
    __u8                 reserve_byte;
    __u16                real_port;
    __u16                real_server_cnt;
    __u16                reserve_short;
    __s32                vitual_if_idx;
    __s32                local_if_idx;
    __u16                min_port;
    __u16                max_port;
};

// this is a coposite structure, cause of reusing bpf map
struct warp_real_server {
    struct warp_sockaddr addr;
    __u32                idx;
};

struct warp_toa {
    __u8  opcode;
    __u8  opsize;
    __u16 port;
    __u32 ip;
};

struct warp_ipv6_toa {
    __u8  opcode;
    __u8  opsize;
    __u16 port;
    __u32 ip[4];
};

struct warp_neigh_event {
    struct warp_sockaddr local;
    struct warp_sockaddr neigh;
};

struct warp_fail_event {
    __u32 code;
};

#endif
