int UPROBE(struct pt_regs *ctx) 
{
	struct pcap *pcap;
	u32 key = 0;
	void *data;	
    u16 len;

	if (!(pcap = xcap_mbuf_scratch.lookup(&key))) {
		return 0;
	}

	data = (void *)PT_REGS_PARM_DATA(ctx);
	len = (u16)PT_REGS_PARM_LEN(ctx);

	__process_user(ctx, pcap, data, data, len, len, TRACE_INDEX);

	return 0;
}
