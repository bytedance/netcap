
static inline void __process_mbuf(struct pt_regs *ctx, struct pcap *pcap, void *ptr_mbuf, u16 trace_index)
{
	u64 mbuf;
	u16 offset;
	u16 data_len;
	u32 pkt_len;

	bpf_probe_read_user(&mbuf, sizeof(mbuf), ptr_mbuf);
	bpf_probe_read_user(&offset, sizeof(offset), (void *)ptr_mbuf + MBUF_DATA_OFFSET);
	bpf_probe_read_user(&data_len, sizeof(data_len), (void *)ptr_mbuf + MBUF_LEN_OFFSET);
	bpf_probe_read_user(&pkt_len, sizeof(pkt_len), (void *)ptr_mbuf + MBUF_PKTLEN_OFFSET);	

	return __process_user(ctx, pcap, (void *)mbuf, (void*)(mbuf+offset), data_len, pkt_len, trace_index);
}

static inline void __process_mbuf_vector(struct pt_regs*ctx, struct pcap* pcap, void **mbufs, u16 mbufs_size, u16 trace_index)
{
	void *addr = 0;

	#pragma unroll
	for (int i = 0; i < MAX_MBUF_ARRAY_SIZE; i++) {
		if (i >= mbufs_size) {
			return;
		}
		bpf_probe_read_user(&addr, sizeof(addr), &mbufs[i]);
		__process_mbuf(ctx, pcap, addr, trace_index);
	}
}
