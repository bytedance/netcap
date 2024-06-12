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
	"testing"

	"github.com/google/gopacket/layers"
)

func TestCbpfFilterNew(t *testing.T) {
	linkType := layers.LinkTypeEthernet
	p, err := New("host 192.168.1.1 and port 80", linkType)
	if err != nil {
		t.Fatalf("new with normal tcpdump expr err : %v", err)
	}
	t.Logf("bpf inst %v", p.cBpfInst)

	b, err := p.ToEbpf()
	if err != nil {
		t.Fatalf("to ebpf err : %v", err)
	}

	t.Logf("ebpf inst %v", b)

	cfunc, err := p.ToC()
	if err != nil {
		t.Fatalf("to c err : %v", err)
	}
	t.Logf("c func %v", cfunc)
}
