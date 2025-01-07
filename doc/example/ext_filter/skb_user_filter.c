
// Return 0 means it's not need, pls filter out it.
static inline int xcap_ext_filter(void *ext, void *pkt, u16 trace_index) 
{
    bpf_trace_printk("user skb filter in index: %d\n", trace_index);
    return 1;
}
