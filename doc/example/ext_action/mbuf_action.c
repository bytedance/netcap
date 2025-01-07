
struct  xcap_user_extend {
    uint64_t    mbuf; // format: 0x%x
    uint16_t    id; // 
    uint16_t    trace_index;
};

// Return 0 means not need to ouput
static inline int xcap_ext_action(void *ext, void *pkt, u32 pkt_len, struct xcap_user_extend *user, u16 trace_index)
{
    user->mbuf = (uint64_t)pkt;

    user->trace_index = trace_index;

    user->id = 0;
    // bpf_trace_printk("user skb action in size %d, idx: %d\n", sizeof(struct xcap_user_extend), trace_index);

    return 1;
}
