
int UPROBE_VECTOR(struct pt_regs *ctx) 
{
	struct pcap *pcap;
	u32 key = 0;
    void **mbufs;
    u16 mbufs_size;
	
    if (!(pcap = xcap_mbuf_scratch.lookup(&key))) {
        return 0;
    }

    mbufs = (void **)pt_regs_parm_vector_mbufs(ctx);
    mbufs_size = (u16)pt_regs_parm_vector_size(ctx);

    __process_mbuf_vector(ctx, pcap, mbufs, mbufs_size, TRACE_INDEX);
    return 0;
}
