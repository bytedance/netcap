
struct TP_STRUCT_args {
    uint8_t     others[TP_SKB_OFFSET];
    void        *skbaddr;
};

int SKB_TRACEPOINT(struct TP_STRUCT_args *args)
{
    struct sk_buff *skb = (struct sk_buff*)(args->skbaddr);

    return __xcap_probe_skb(args, skb, TRACE_INDEX);
}
