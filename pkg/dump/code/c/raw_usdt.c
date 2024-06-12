int USDT(struct pt_regs *ctx) 
{
	struct pcap *pcap;
	u32 key = 0;
	void* data = 0;
    u16 len;

	if (!(pcap = xcap_mbuf_scratch.lookup(&key))) {
        return 0;
    }

	bpf_usdt_readarg(PARAM_INDEX_1, ctx, &data);
    bpf_usdt_readarg(PARAM_INDEX_2, ctx, &len);

	__process_user(ctx, pcap, data, data, len, len, TRACE_INDEX);

	return 0;
}