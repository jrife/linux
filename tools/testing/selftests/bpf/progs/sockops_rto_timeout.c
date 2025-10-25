// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETIMEDOUT 110

int rto = 0;

SEC("sockops")
int rto_timeout(struct bpf_sock_ops *skops)
{
	int ret = 0;

	switch (skops->op) {
	case BPF_SOCK_OPS_TCP_CONNECT_CB:
	case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_RTO_CB_FLAG);
		break;
	case BPF_SOCK_OPS_RTO_CB:
		__sync_fetch_and_add(&rto, 1);
		skops->reply = -ETIMEDOUT;
		ret = 1;
		break;
	default:
		break;
	}

	return ret;
}


char _license[] SEC("license") = "GPL";
