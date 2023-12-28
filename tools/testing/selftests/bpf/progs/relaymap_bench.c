// SPDX-License-Identifier: GPL-2.0
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpf_misc.h"

char _license[] SEC("license") = "GPL";

extern int bpf_relay_output(struct bpf_map *map, void *data,
			    __u64 data__sz, __u32 flags) __ksym;

struct {
	__uint(type, BPF_MAP_TYPE_RELAY);
	__uint(map_flags, BPF_F_OVERWRITE);
	/* bufsize = 8 * 64 * 1024 = 128 * 4096 */
	__uint(max_entries, 64 * 1024);
	__uint(map_extra, 8);
} relaymap SEC(".maps");

const volatile int batch_cnt = 0;

long sample_val = 42;
long dropped __attribute__((aligned(128))) = 0;

SEC("fentry/" SYS_PREFIX "sys_getpgid")
int bench_relaymap(void *ctx)
{
	int i;

	for (i = 0; i < batch_cnt; i++) {
		if (bpf_relay_output((struct bpf_map *)&relaymap, &sample_val,
				     sizeof(sample_val), 0))
			__sync_add_and_fetch(&dropped, 1);
	}
	return 0;
}
