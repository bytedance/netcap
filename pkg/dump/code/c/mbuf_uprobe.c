
int UPROBE(struct pt_regs *ctx) 
{
	struct pcap *pcap;
	u32 key = 0;
	void *mbuf_ptr;	

	if (!(pcap = xcap_mbuf_scratch.lookup(&key))) {
		return 0;
	}

	mbuf_ptr = (void *)PT_REGS_PARM_MBUF(ctx);
	__process_mbuf(ctx, pcap, mbuf_ptr, TRACE_INDEX);

	return 0;
}
