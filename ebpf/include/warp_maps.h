#ifndef __WARP_MAPS_H__
#define __WARP_MAPS_H__

#include "warp_structs.h"

#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// map #0
struct bpf_map_def SEC("maps") warp_map_in_real_server = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(struct warp_real_server),
    .max_entries = 1 << 10,
};
/*
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct warp_real_server);
    __uint(max_entries, 1 << 10);
} warp_map_in_real_server SEC(".maps");
*/
// map #1
struct bpf_map_def SEC("maps") warp_map_in_port = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1 << 16,
};

// map #2
struct bpf_map_def SEC("maps") warp_map_nat_service = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct warp_sockaddr),
    .value_size  = sizeof(struct warp_service),
    .max_entries = 1 << 8,
};

// map #3
struct bpf_map_def SEC("maps") warp_map_nat_real_server = {
    .type          = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size      = sizeof(struct warp_sockaddr),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    .value_size    = sizeof(__u32),
#else
    .inner_map_idx = 0,
#endif
    .max_entries   = 1 << 8,
};

// map #4
struct bpf_map_def SEC("maps") warp_map_nat_connection = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct warp_connection),
    .value_size  = sizeof(struct warp_redirect),
    .max_entries = 1 << 17,
};

// map #5
struct bpf_map_def SEC("maps") warp_map_fnat_service = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct warp_sockaddr),
    .value_size  = sizeof(struct warp_service),
    .max_entries = 1 << 8,
};
/*
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct warp_sockaddr);
    __type(value, struct warp_service);
    __uint(max_entries, 1 << 8);
} warp_map_fnat_service SEC(".maps");
*/
// map #6
struct bpf_map_def SEC("maps") warp_map_fnat_real_server = {
    .type          = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size      = sizeof(struct warp_sockaddr),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    .value_size    = sizeof(__u32),
#else
    .inner_map_idx = 0,
#endif
    .max_entries   = 1 << 8,
};

// map #7
struct bpf_map_def SEC("maps") warp_map_fnat_port = {
    .type          = BPF_MAP_TYPE_HASH_OF_MAPS,
    .key_size      = sizeof(__u32),
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0)
    .value_size    = sizeof(__u32),
#else
    .inner_map_idx = 1,
#endif
    .max_entries   = 1 << 8,
};

// map #8
struct bpf_map_def SEC("maps") warp_map_fnat_connection = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(struct warp_connection),
    .value_size  = sizeof(struct warp_redirect),
    .max_entries = 1 << 17,
};

// map #9
struct bpf_map_def SEC("maps") warp_map_fnat_release_port = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1 << 16,
};

// map #10
struct bpf_map_def SEC("maps") warp_map_nat_event = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(__u32),
    .max_entries = 1200,
};

// map #11
struct bpf_map_def SEC("maps") warp_map_fnat_event = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(__u32),
    .max_entries = 1200,
};

// map #12
struct bpf_map_def SEC("maps") warp_map_fail_event = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(int),
    .value_size  = sizeof(__u32),
    .max_entries = 1200,
};

#endif