
// xcap skb -f __ip_finish_output@3 -e "udp and host 10.227.0.72" -t "-nnv" 

struct  xcap_user_extend {
    int skb_len;
    int skb_datalen;

    uint32_t gso_size;
    uint32_t gso_segs;
    uint32_t gso_type; // format: 0x%x
};

static inline int xcap_skb_action(void *ext, void *pkt, u32 pkt_len, struct xcap_user_extend *user, u16 trace_index)
{
    struct sk_buff *skb;
    struct skb_shared_info *info;
    void *head;
    uint32_t end;

    skb = (struct sk_buff *)pkt;

    head = _(skb->head);
    end = _(skb->end);
    info = (struct skb_shared_info *)(head + end);

    user->skb_len = skb->len;
    user->skb_datalen = skb->data_len;

    user->gso_size = _(info->gso_size);
    user->gso_segs = _(info->gso_segs);
    user->gso_type = _(info->gso_type);

    return 1;
}
