
BPF_PERCPU_ARRAY(xcap_skb_scratch, struct pcap, 1);

#ifdef STACK_DUMP
BPF_STACK_TRACE(xcap_stack, 2048);
#endif

BPF_PERF_OUTPUT(xcap_pcap_event);

static inline void skb_capture_event_notify(void *ctx, struct sk_buff *skb, u32 len, struct pcap *pcap, void *ext)
{
#ifdef STACK_DUMP
    pcap->hdr.stack_id = xcap_stack.get_stackid(ctx, 0);
#endif

#ifdef ENABLE_EXT_ACTION
	pcap->hdr.extend_action_ret = xcap_ext_action(ext, skb, len, &pcap->user, pcap->hdr.trace_position_index);
#endif
	xcap_pcap_event.perf_submit(ctx, pcap, sizeof(*pcap));
}

#ifdef CONFIG_IFINDEX
static inline int filter_by_ifindex(struct sk_buff *skb) {
    struct net_device *dev = NULL;
	int ifindex = 0;

    if (CONFIG_IFINDEX == 0) {
        return 1;
    }

	dev = _(skb->dev);
	ifindex = _(dev->ifindex);

    if (ifindex == CONFIG_IFINDEX) {
        return 1;
    }

    return 0;
}
#endif /* CONFIG_IFINDEX */
