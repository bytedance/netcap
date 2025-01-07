
#ifdef SK_PROTO_16BIT

static inline u8 sk_get_proto(struct sock *sk)
{
	return _(sk->sk_protocol);
}

#else //!SK_PROTO_16BIT

static inline u8 sk_get_proto(struct sock *sk)
{
	return (_(sk->__sk_flags_offset[0]) & SK_FL_PROTO_MASK) >> SK_FL_PROTO_SHIFT;
}

#endif //SK_PROTO_16BIT

static inline int skb_init_fake_ethhdr(struct sk_buff *skb, struct ethhdr *eth)
{
	if (_(skb->protocol)) {
		eth->h_proto = _(skb->protocol);
	} else if (_(skb->sk)) {
		struct sock *sk = _(skb->sk);

		switch (_(sk->sk_family)) {
		case AF_INET:
			eth->h_proto = htons(ETH_P_IP);
			break;
		case AF_INET6:
			eth->h_proto = htons(ETH_P_IPV6);
			break;
		default:
			goto err;
		}
	}
	return 0;
err:
	return -1;
}

static inline int __skb_init_fake_iphdr(struct sk_buff *skb, struct iphdr *iph, int tot_len)
{
	u8 tos = 0;
	struct sock *sk = _(skb->sk);

	*((u16 *)iph) = htons((4 << 12) | (5 << 8) | (tos & 0xff));
	iph->tot_len = htons(tot_len);
	iph->protocol = sk_get_proto(sk);
	iph->saddr = _(sk->sk_rcv_saddr);
	iph->daddr = _(sk->sk_daddr);

	return 0;
err:
	return -1;
}

static inline int skb_init_fake_iphdr(struct sk_buff *skb, struct iphdr *iph, int tot_len)
{
	if (!_(skb->sk))
		goto err;

	return __skb_init_fake_iphdr(skb, iph, tot_len);
err:
	return -1;
}

static inline int __skb_init_fake_ipv6hdr(struct sk_buff *skb, struct ipv6hdr *ip6h, int payload_len)
{
	u32 flowlabel = 0;
	unsigned int tclass = 0;
	struct sock *sk = _(skb->sk);

	*(u32 *)ip6h = htonl(0x60000000 | (tclass << 20)) | flowlabel;
	ip6h->payload_len = htons(payload_len);
	ip6h->nexthdr = sk_get_proto(sk);
	ip6h->saddr = _(sk->sk_v6_rcv_saddr);
	ip6h->daddr = _(sk->sk_v6_daddr);

	return 0;
err:
	return -1;
}

static inline int skb_init_fake_ipv6hdr(struct sk_buff *skb, struct ipv6hdr *ip6h, int payload_len)
{
	if (!_(skb->sk))
		goto err;

	return __skb_init_fake_ipv6hdr(skb, ip6h, payload_len);
err:
	return -1;
}

static inline int __xcap_probe_skb(void *ctx, struct sk_buff *skb, void *ext, u16 trace_index)
{
	int headlen, copylen, pullen, pkt_len = 0;
	void *data;
	struct pcap *pcap;
	u32 key = 0, offset = 0;
	u16 caplen;

	if (!(pcap = xcap_skb_scratch.lookup(&key)))
		goto end;

#ifdef CONFIG_IFINDEX
	if (!filter_by_ifindex(skb)) {
		goto end;
	}
#endif

	// mac header was set
	if (_(skb->mac_header) != (u16)~0U) {
		data = (void *)(_(skb->head) + _(skb->mac_header));
		pullen = (unsigned long)_(skb->data) - (unsigned long)data;


	} else if (_(skb->network_header)) {
		if (skb_init_fake_ethhdr(skb, (struct ethhdr *)pcap->buf))
			goto end;

		data = (void *)(_(skb->head) + _(skb->network_header));
		offset = sizeof(struct ethhdr);
	} else if (_(skb->transport_header) != (u16)~0U) {
		struct ethhdr *eth = (struct ethhdr *)pcap->buf;

		if (skb_init_fake_ethhdr(skb, eth))
			goto end;

		switch (eth->h_proto) {
		case ntohs(ETH_P_IP):
			if (skb_init_fake_iphdr(skb,
				(struct iphdr *)(pcap->buf + sizeof(struct ethhdr)),
				_(skb->len) + sizeof(struct iphdr)))
				goto end;

			offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
			break;
		case ntohs(ETH_P_IPV6):
			if (skb_init_fake_ipv6hdr(skb,
				(struct ipv6hdr *)(pcap->buf + sizeof(struct ethhdr)),
				_(skb->len)))
				goto end;

			offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
			break;
		default:
			goto end;
		}

		data = (void *)(_(skb->head) + _(skb->transport_header));
	} else {
		goto end;
	} 

	caplen = sizeof(pcap->buf);
	headlen = _(skb->len) - _(skb->data_len) + offset + pullen;
    pkt_len = _(skb->len) + offset + pullen;
	
	if (headlen < caplen)
		caplen = headlen;

	copylen = caplen - offset;
	if (copylen > sizeof(pcap->buf) - offset)
		goto end;

	if (bpf_probe_read_kernel(pcap->buf + offset, copylen, data))
		goto end;

#ifdef ENABLE_FILTER
	if (!do_filter(pcap->buf, pcap->buf + caplen)) {
		goto end;
	}
#endif

#ifdef ENABLE_EXT_FILTER
	if (!xcap_ext_filter(ext, skb, trace_index)) {
		goto end;
	}
#endif

	__pcap_fill_header(pcap, skb, pkt_len, caplen, trace_index);
	skb_capture_event_notify(ctx, skb, pkt_len, pcap, ext);

end:
	return 0;
}


