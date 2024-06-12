
int USDT_VECTOR(struct pt_regs *ctx) 
{
	struct pcap *pcap;
	u32 key = 0;
    void **mbufs;
	u16 mbufs_size;

	if (!(pcap = xcap_mbuf_scratch.lookup(&key))) {
        return 0;
    }

	bpf_usdt_readarg(PARAM_INDEX_1, ctx, &mbufs);
	bpf_usdt_readarg(PARAM_INDEX_2, ctx, &mbufs_size);

	__process_mbuf_vector(ctx, pcap, mbufs, mbufs_size, TRACE_INDEX);

	return 0;
}

