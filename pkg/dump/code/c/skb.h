#include <net/sock.h>
#include <linux/skbuff.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/in.h>

#define _(P) ({typeof(P) val; bpf_probe_read_kernel(&val, sizeof(val), &P); val;})
