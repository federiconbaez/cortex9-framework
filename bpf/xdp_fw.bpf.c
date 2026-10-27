// SPDX-License-Identifier: GPL-2.0-only OR Apache-2.0
/*
 * cortex9 XDP firewall.
 *
 * This is a line-by-line mirror of crates/c9-classify/src/engine.rs. The
 * rules live in BPF maps written by userspace from the shared policy, so a
 * policy change is a handful of map updates: the program is never reloaded
 * or re-attached. Rules are double-buffered: two epochs of maps, and a
 * one-word selector that is read once per packet, so a reload is atomic
 * from the point of view of any single packet. The differential test in crates/c9-xdp runs this program
 * through BPF_PROG_TEST_RUN and the Rust engine on identical frames.
 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define C9_MAX_PREFIXES 4096
#define C9_MAX_PORTS 1024

/* Must match c9_classify::Reason. */
enum c9_reason {
	PASS_NOT_IPV4 = 0,
	PASS_ALLOW_SRC = 1,
	PASS_DEFAULT = 2,
	DROP_DENY_SRC = 3,
	DROP_DENY_PORT = 4,
	DROP_MALFORMED = 5,
	DROP_FRAGMENT = 6,
	PASS_MALFORMED = 7,
	PASS_FRAGMENT = 8,
	C9_REASON_COUNT = 9,
};

#define C9_F_DROP_MALFORMED 1u
#define C9_F_DROP_FRAGMENTS 2u

struct c9_lpm_key {
	__u32 prefixlen;
	__u32 addr; /* network byte order */
};

/* Per-epoch settings. Two epochs exist; userspace fills the inactive one and
 * then flips c9_active, so every packet sees one complete policy. */
struct c9_epoch {
	__u32 flags;
	__u32 reserved;
	__u64 generation;
	__u64 fingerprint;
};

#define C9_LPM_MAP(name)                                     \
	struct {                                             \
		__uint(type, BPF_MAP_TYPE_LPM_TRIE);         \
		__uint(max_entries, C9_MAX_PREFIXES);        \
		__uint(map_flags, BPF_F_NO_PREALLOC);        \
		__type(key, struct c9_lpm_key);              \
		__type(value, __u8);                         \
		__uint(pinning, LIBBPF_PIN_BY_NAME);         \
	} name SEC(".maps")

#define C9_PORT_MAP(name)                                    \
	struct {                                             \
		__uint(type, BPF_MAP_TYPE_HASH);             \
		__uint(max_entries, C9_MAX_PORTS);           \
		__type(key, __u32); /* proto << 16 | port */ \
		__type(value, __u8);                         \
		__uint(pinning, LIBBPF_PIN_BY_NAME);         \
	} name SEC(".maps")

C9_LPM_MAP(c9_allow_0);
C9_LPM_MAP(c9_allow_1);
C9_LPM_MAP(c9_deny_0);
C9_LPM_MAP(c9_deny_1);
C9_PORT_MAP(c9_ports_0);
C9_PORT_MAP(c9_ports_1);

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct c9_epoch);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} c9_epoch SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} c9_active SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, C9_REASON_COUNT);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} c9_stats SEC(".maps");

static __always_inline __u16 load_be16(const void *p)
{
	return bpf_ntohs(*(const __u16 *)p);
}

static __always_inline __u32 c9_classify(void *data, void *end, __u32 flags, __u32 epoch)
{
	__u32 malformed = (flags & C9_F_DROP_MALFORMED) ? DROP_MALFORMED : PASS_MALFORMED;
	__u32 l3 = 14;
	__u16 ethertype;

	if (data + 14 > end)
		return PASS_NOT_IPV4;
	ethertype = load_be16(data + 12);
	if (ethertype == 0x8100 || ethertype == 0x88A8) {
		if (data + 18 > end)
			return PASS_NOT_IPV4;
		ethertype = load_be16(data + 16);
		l3 = 18;
	}
	if (ethertype != 0x0800)
		return PASS_NOT_IPV4;

	__u8 *ip = data + l3;
	if ((void *)(ip + 20) > end)
		return malformed;
	__u8 vihl = ip[0];
	if ((vihl >> 4) != 4)
		return malformed;
	__u32 ihl = (vihl & 0x0f) * 4;
	if (ihl < 20)
		return malformed;
	if ((void *)(ip + ihl) > end)
		return malformed;
	if (load_be16(ip + 2) < ihl)
		return malformed;

	struct c9_lpm_key key = { .prefixlen = 32, .addr = *(__u32 *)(ip + 12) };
	if (epoch ? !!bpf_map_lookup_elem(&c9_allow_1, &key) : !!bpf_map_lookup_elem(&c9_allow_0, &key))
		return PASS_ALLOW_SRC;
	if (epoch ? !!bpf_map_lookup_elem(&c9_deny_1, &key) : !!bpf_map_lookup_elem(&c9_deny_0, &key))
		return DROP_DENY_SRC;

	__u16 frag = load_be16(ip + 6);
	if (frag & 0x1fff)
		return (flags & C9_F_DROP_FRAGMENTS) ? DROP_FRAGMENT : PASS_FRAGMENT;
	if ((frag & 0x2000) && (flags & C9_F_DROP_FRAGMENTS))
		return DROP_FRAGMENT;

	__u8 proto = ip[9];
	if (proto == 6 || proto == 17) {
		if ((void *)(ip + ihl + 4) > end)
			return malformed;
		__u32 pk = ((__u32)proto << 16) | load_be16(ip + ihl + 2);
		if (epoch ? !!bpf_map_lookup_elem(&c9_ports_1, &pk) : !!bpf_map_lookup_elem(&c9_ports_0, &pk))
			return DROP_DENY_PORT;
	}
	return PASS_DEFAULT;
}

SEC("xdp")
int c9_xdp(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;
	__u32 zero = 0;
	/* Read the selector exactly once per packet. */
	__u32 *active = bpf_map_lookup_elem(&c9_active, &zero);
	__u32 epoch = active ? (*active & 1) : 0;
	struct c9_epoch *ep = bpf_map_lookup_elem(&c9_epoch, &epoch);
	__u32 flags = ep ? ep->flags : C9_F_DROP_MALFORMED;
	__u32 reason = c9_classify(data, end, flags, epoch);
	__u64 *cnt = bpf_map_lookup_elem(&c9_stats, &reason);

	if (cnt)
		*cnt += 1;
	if (reason == DROP_DENY_SRC || reason == DROP_DENY_PORT || reason == DROP_MALFORMED ||
	    reason == DROP_FRAGMENT)
		return XDP_DROP;
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
