
int USDT(struct pt_regs *ctx) 
{
	struct pcap *pcap;
	u32 key = 0;
	void *mbuf_ptr;

	if (!(pcap = xcap_mbuf_scratch.lookup(&key))) {
        return 0;
    }

	bpf_usdt_readarg(PARAM_INDEX_1, ctx, &mbuf_ptr);
	__process_mbuf(ctx, pcap, mbuf_ptr, TRACE_INDEX);	

	return 0;
}

