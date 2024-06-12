#ifndef MBUF_DATA_OFFSET
#define MBUF_DATA_OFFSET		16
#endif //MBUF_DATA_OFFSET

#ifndef MBUF_LEN_OFFSET
#define MBUF_LEN_OFFSET 		40
#endif

#ifndef MBUF_PKTLEN_OFFSET
#define MBUF_PKTLEN_OFFSET 		36
#endif

#ifndef MAX_MBUF_ARRAY_SIZE
#define MAX_MBUF_ARRAY_SIZE     512
#endif //MAX_MBUF_ARRAY_SIZE

BPF_PERCPU_ARRAY(xcap_mbuf_scratch, struct pcap, 1);

BPF_PERF_OUTPUT(xcap_pcap_event);

static inline void mbuf_capture_event_notify(struct pt_regs *ctx, void *ptr_mbuf, struct pcap *pcap, u16 trace_index) 
{
	xcap_pcap_event.perf_submit(ctx, pcap, sizeof(*pcap));
}

static inline void __process_user(struct pt_regs *ctx, struct pcap *pcap, void *ptr_pkt, 
				void *udata, u16 len, u32 pkt_len, u16 trace_index)
{
    u16 cap_len;

    bpf_probe_read_user(pcap->buf, sizeof(pcap->buf), udata);

    cap_len = len;
	if (cap_len > sizeof(pcap->buf)) {
		cap_len = sizeof(pcap->buf);
	}

#ifdef ENABLE_FILTER
	if (!do_filter(pcap->buf, pcap->buf + cap_len))
		return;
#endif

#ifdef ENABLE_USER_FILTER
	if (!xcap_user_filter(ctx, ptr_pkt, trace_index)) 
		return;
#endif

	__pcap_fill_header(pcap, ptr_pkt, pkt_len, cap_len, trace_index);

#ifdef ENABLE_USER_ACTION
	pcap->hdr.extend_action_ret = xcap_user_action(ctx, ptr_pkt, pkt_len, &pcap->user, trace_index);
#endif
	
	mbuf_capture_event_notify(ctx, ptr_pkt, pcap, trace_index);

}
