
static inline int __xcap_probe_skb(void *ctx, struct sk_buff *skb, u16 trace_index)
{
	u32 pkt_len, liner_len, pullen = 0;
	void *data;
	struct pcap *pcap;
	u32 key = 0;
	void *skb_head, *skb_data;
	u32 skb_len, skb_datalen;
	u32 copy_liner_len;
	u16 caplen;

	if (!(pcap = xcap_skb_scratch.lookup(&key)))
		goto end;

#ifdef CONFIG_IFINDEX
	if (!filter_by_ifindex(skb)) {
		goto end;
	}
#endif

	skb_head = (void*)(_(skb->head));
	skb_data = (void*)(_(skb->data));
	skb_len = _(skb->len);
	skb_datalen = _(skb->data_len);

	// mac header was set
	if (_(skb->mac_header) != (u16)~0U) {
		data = (void *)(skb_head + _(skb->mac_header));
		pullen = skb_data - data;
	} else {
		data = skb_head;
		pullen = 0;
	}
	
	XCAP_FIX_DATA

	liner_len = skb_len - skb_datalen + pullen;
	pkt_len = skb_len + pullen;

	copy_liner_len = liner_len > sizeof(pcap->buf) ? sizeof(pcap->buf) : liner_len;

	if (copy_liner_len > sizeof(pcap->buf))
		goto end;

	if (bpf_probe_read_kernel(pcap->buf, copy_liner_len, data))
		goto end;

	caplen = copy_liner_len;

#ifdef ENABLE_FILTER
	if (!do_filter(pcap->buf, pcap->buf + caplen)) {
		goto end;
	}
#endif

#ifdef ENABLE_USER_FILTER
	if (!xcap_user_filter(ctx, skb, trace_index)) {
		goto end;
	}
#endif

	__pcap_fill_header(pcap, skb, pkt_len, caplen, trace_index);
	skb_capture_event_notify(ctx, skb, pkt_len, pcap);

end:
	return 0;
}

