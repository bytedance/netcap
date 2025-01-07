// Comm function in skb and mbuf
struct pcap_hdr {
	void *ptr;
	u64 time_stamp;
	u32 len;
	u16 extend_offset;
	u16 buf_offset;
	u16 caplen;
	u16 trace_position_index;
	int extend_action_ret;
	u32 stack_id;
	u32 reserved;
};

#ifdef ENABLE_EXT_ACTION

#else
struct xcap_user_extend {

};
#endif

struct pcap {
	struct pcap_hdr hdr;

	struct xcap_user_extend user;

	u8 buf[CAPTURE_LEN];
};

static inline void __pcap_fill_header(struct pcap* pcap, void *ptr, u32 len, u32 caplen, u16 trace_index)
{
	pcap->hdr.time_stamp = bpf_ktime_get_ns();
	pcap->hdr.ptr = ptr;
	pcap->hdr.len = len;

	pcap->hdr.extend_offset = (void*)(&pcap->user) - (void*)pcap;
	pcap->hdr.buf_offset = (void*)pcap->buf - (void *)pcap;

	pcap->hdr.caplen = (u16)caplen;
	pcap->hdr.trace_position_index = trace_index;
	pcap->hdr.extend_action_ret = 0;
}

