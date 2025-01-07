// xcap skb -f tcp_rcv_established@2@1 -e "port 8888"  --ext-action sk_stat_action.c

#include <linux/tcp.h>

struct  xcap_user_extend {
    int         state; // format: 0x%x
    int         segs_in;
};

// Return 0 means not need to ouput
static inline int xcap_ext_action(void *ext, void *pkt, u32 pkt_len, struct xcap_user_extend *user, u16 trace_index)
{
    struct sock *sk = (struct sock*)ext;
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    if (sk == NULL) {
        bpf_trace_printk("cat not get sk\n");
        return 0;
    }

    user->state = sk->__sk_common.skc_state;
    user->segs_in = tp->segs_in;
    return 1;
}
