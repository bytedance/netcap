

struct  xcap_user_extend {
    int         a; // format: 0x%x
    uint32_t    b; // 

    int64_t     c;     
    uint8_t       x1; // format: %c
    uint8_t       x2; // format: 0x%x
    uint16_t      x3; // format: 0x%x
};

// Return 0 means not need to ouput
static inline int xcap_ext_action(void *ext, void *pkt, u32 pkt_len, struct xcap_user_extend *user, u16 trace_index)
{
    user->a = 0x12345678;
    user->b = 1000;
    user->c = 2002;
    user->x1 = 'M';
    user->x2 = 0x11;
    user->x3 = 0xabcd;
    bpf_trace_printk("user skb action in size %d, idx: %d\n", sizeof(struct xcap_user_extend), trace_index);

    return 1;
}
