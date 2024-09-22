//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

SEC("tc")
int hook1(struct __sk_buff *skb) {
	bpf_printk("hook1\n");
	return 0;
}

SEC("tc")
int hook2(struct __sk_buff *skb) {
	bpf_printk("hook2\n");
	return 0;
}

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 2);
	__uint(key_size, sizeof(__u32));
	__array(values, int(void *));
} hooks SEC(".maps") = {
	.values =
		{
			[0] = (void *)&hook1,
			[1] = (void *)&hook2,
		},
};

static __noinline int call_hook_1(struct __sk_buff *skb) {
	bpf_tail_call(skb, &hooks, 0);
	return 0;
}

static __noinline int call_hook_2(struct __sk_buff *skb) {
	bpf_tail_call(skb, &hooks, 1);
	return 0;
}

SEC("tc")
int ingress_prog_func(struct __sk_buff *skb) {
	int ret = 0;

	ret = call_hook_1(skb);
	bpf_printk("after hook 1 = %d\n", ret);
	ret = call_hook_2(skb);
	bpf_printk("after hook 2 = %d\n", ret);

	return 0;
}
