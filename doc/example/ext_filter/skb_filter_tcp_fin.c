struct _tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
	__u16	flags;
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
static inline int xcap_ext_filter(void *ext, void *pkt, u16 trace_index)
{
	struct _tcphdr *tp;
	struct sk_buff *skb = (struct sk_buff *)pkt;

	tp = (struct _tcphdr*)(skb->head + skb->transport_header);

	// FIN
	if (tp->flags & 0x0100 ) {
		return 1;
	}

	return 0;

}
