// +build ignore

#include "warp_structs.h"
#include "warp_maps.h"
#include "warp_helpers.h"
#include "warp_csum_helpers.h"

static __always_inline struct warp_sockaddr* select_real_server(struct warp_service *srv, struct warp_sockaddr *key, __u32 cpu)
{
    __u32 *inner_fd = bpf_map_lookup_elem(&warp_map_nat_real_server, key);
    if (!inner_fd) {
        return 0;
    }

    struct warp_real_server *val = bpf_map_lookup_elem(inner_fd, &cpu);
    if (!val) {
        return 0;
    }

    __u32 inner_key = val->idx;
    val->idx++;
    if (val->idx >= srv->real_server_cnt) {
        val->idx = 0;
    }

    val = bpf_map_lookup_elem(inner_fd, &inner_key);
    if (!val) {
        return 0;
    }
    return &val->addr;
}

static __always_inline enum warp_action get_or_gen_conn(struct warp_context *ctx)
{
    // forward
    struct warp_connection fwd_key;
    __builtin_memset(&fwd_key, 0, sizeof(fwd_key));
    fwd_key.saddr.l4_proto = ctx->l4_proto;
    fwd_key.daddr.l4_proto = ctx->l4_proto;
    if (ctx->is_ipv6) {
        fwd_key.saddr.af = AF_INET6;
        fwd_key.daddr.af = AF_INET6;
        __builtin_memcpy(&fwd_key.saddr.addr6, &(((struct ipv6hdr*)ctx->l3h)->saddr), 16);
        __builtin_memcpy(&fwd_key.daddr.addr6, &(((struct ipv6hdr*)ctx->l3h)->daddr), 16);
    } else {
        fwd_key.saddr.af = AF_INET;
        fwd_key.daddr.af = AF_INET;
        fwd_key.saddr.addr4.addr = ((struct iphdr*)ctx->l3h)->saddr;
        fwd_key.daddr.addr4.addr = ((struct iphdr*)ctx->l3h)->daddr;
    }
    fwd_key.saddr.port = ((struct udphdr*)ctx->l4h)->source;
    fwd_key.daddr.port = ((struct udphdr*)ctx->l4h)->dest;

    struct warp_redirect *fwd_val = bpf_map_lookup_elem(&warp_map_nat_connection, &fwd_key);
    if (fwd_val) {
        ctx->forward = *fwd_val;
        fwd_val->ts  = bpf_ktime_get_ns();
        return WARP_ACT_OK;
    }

    struct warp_service *srv = bpf_map_lookup_elem(&warp_map_nat_service, &fwd_key.daddr);
    if (!srv || !srv->real_server_cnt) {
        return WARP_ACT_PASS;
    }

    struct warp_sockaddr *rs = select_real_server(srv, &fwd_key.daddr, ctx->cpu);
    if (!rs) {
        return WARP_ACT_DROP;
    }

    // build forward redirect data
    ctx->forward.redirect.saddr      = fwd_key.saddr;
    ctx->forward.redirect.daddr      = *rs;
    ctx->forward.redirect.daddr.port = srv->real_port;
    ctx->forward.redirect_if_idx     = srv->local_if_idx;
    ctx->forward.ts                  = bpf_ktime_get_ns();
    ctx->forward.positive            = WARP_SET;

    // reverse
    struct warp_connection rvs_key;
    rvs_key.saddr = ctx->forward.redirect.daddr;
    rvs_key.daddr = ctx->forward.redirect.saddr;

    // build reverse conn redirect data
    struct warp_redirect reverse;
    __builtin_memset(&reverse, 0, sizeof(reverse));
    reverse.redirect.saddr  = fwd_key.daddr;
    reverse.redirect.daddr  = fwd_key.saddr;
    reverse.redirect_if_idx = srv->vitual_if_idx;
    reverse.ts              = ctx->forward.ts;

    long update_ret = bpf_map_update_elem(&warp_map_nat_connection, &fwd_key, &ctx->forward, BPF_NOEXIST);
    if (update_ret) {
        return WARP_ACT_DROP;
    }
    update_ret = bpf_map_update_elem(&warp_map_nat_connection, &rvs_key, &reverse, BPF_NOEXIST);
    if (update_ret) {
        bpf_map_delete_elem(&warp_map_nat_connection, &fwd_key);
        return WARP_ACT_DROP;
    }

    return WARP_ACT_OK;
}

SEC("xdp_nat")
int warp_xdp_nat(struct xdp_md *xdp_ctx)
{
    struct warp_context ctx;
    __builtin_memset(&ctx, 0, sizeof(ctx));
    ctx.end       = (void*)(long)xdp_ctx->data_end;
    ctx.begin     = (void*)(long)xdp_ctx->data;
    ctx.stack_ctx = (void*)xdp_ctx;
    ctx.cpu       = bpf_get_smp_processor_id();

    enum warp_action act = warp_parse_ctx(&ctx);
    if (act != WARP_ACT_OK) {
        return warp_xdp_act(act);
    }

    act = get_or_gen_conn(&ctx);
    if (act != WARP_ACT_OK) {
        return warp_xdp_act(act);
    }

    act = warp_swap_addr(&ctx);
    if (act != WARP_ACT_OK) {
        if (act == WARP_ACT_UNREACH) {
            struct warp_neigh_event ev;
            ev.local = ctx.forward.redirect.saddr;
            ev.neigh = ctx.forward.redirect.daddr;
            bpf_perf_event_output(ctx.stack_ctx, &warp_map_nat_event, BPF_F_CURRENT_CPU, &ev, sizeof(ev));
        }
        return warp_xdp_act(act);
    }

    act = warp_dec_ttl(&ctx);
    if (act != WARP_ACT_OK) {
        return warp_xdp_act(act);
    }

    warp_update_ip_csum(&ctx);
    warp_update_l4_csum_incre(&ctx);

    return bpf_redirect(ctx.forward.redirect_if_idx, 0);
}

char __license[] SEC("license") = "GPL";
