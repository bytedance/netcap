
int SKB_KPROBE(struct pt_regs *ctx)
{
	struct sk_buff *skb;
	void *ext = NULL;

	SKB_SET_EXT_PARAM

	if (!(skb = (struct sk_buff *)SKB_REGS_PARAM_X(ctx))) {
		return 0;
	}

	return __xcap_probe_skb(ctx, skb, ext, TRACE_INDEX);
}
