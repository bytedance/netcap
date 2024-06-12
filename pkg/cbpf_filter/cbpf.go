/*
Copyright 2024 ByteDance and/or its affiliates.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cbpf_filter

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf/asm"
	"github.com/cloudflare/cbpfc"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pkg/errors"
	"golang.org/x/net/bpf"
)

type CbpfFilter struct {
	linkType layers.LinkType
	cBpfInst []bpf.Instruction
}

func New(expr string, linkType layers.LinkType) (*CbpfFilter, error) {
	p := &CbpfFilter{
		linkType: linkType,
	}

	expr = strings.TrimSpace(expr)
	inst, err := TcpdumpExprToBPF(expr, linkType)
	if err != nil {
		return nil, fmt.Errorf("tcpdump expr %v to bpf err : %v", expr, err)
	}
	p.cBpfInst = inst

	return p, nil
}

func (p *CbpfFilter) ToEbpf() (asm.Instructions, error) {
	return p.ToEbpfWithOption(cbpfc.EBPFOpts{
		PacketStart: asm.R0,
		PacketEnd:   asm.R1,

		Result:      asm.R2,
		ResultLabel: "result",

		Working: [4]asm.Register{asm.R2, asm.R3, asm.R4, asm.R5},

		StackOffset: 0,
		LabelPrefix: "filter",
	})
}

func (p *CbpfFilter) ToEbpfWithOption(opts cbpfc.EBPFOpts) (asm.Instructions, error) {
	return cbpfc.ToEBPF(p.cBpfInst, opts)
}

func (p *CbpfFilter) ToC() (string, error) {
	return p.ToCWithOption(cbpfc.COpts{
		FunctionName: "do_filter",
	})
}

func (p *CbpfFilter) ToCWithOption(opts cbpfc.COpts) (string, error) {
	return cbpfc.ToC(p.cBpfInst, opts)
}

// tcpdumpExprToBPF converts a tcpdump / libpcap filter expression to cBPF using libpcap
func TcpdumpExprToBPF(filterExpr string, linkType layers.LinkType) ([]bpf.Instruction, error) {
	// We treat any != 0 filter return code as a match
	insns, err := pcap.CompileBPFFilter(linkType, 1, filterExpr)
	if err != nil {
		return nil, errors.Wrap(err, "compiling expression to BPF")
	}

	return pcapInsnToX(insns), nil
}

func pcapInsnToX(insns []pcap.BPFInstruction) []bpf.Instruction {
	xInsns := make([]bpf.Instruction, len(insns))

	for i, insn := range insns {
		xInsns[i] = bpf.RawInstruction{
			Op: insn.Code,
			Jt: insn.Jt,
			Jf: insn.Jf,
			K:  insn.K,
		}.Disassemble()
	}

	return xInsns
}
