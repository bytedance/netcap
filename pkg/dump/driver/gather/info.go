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
package gather

import (
	"container/list"
	"time"

	"github.com/bytedance/netcap/pkg/dump/xproto"
)

type Item struct {
	Received  bool
	LatencyNs uint64
}

type GatherInfo struct {
	// base packet:
	Packet *xproto.PcapCaputre
	Items  []Item

	elemet *list.Element
	time   time.Time
}

func newGatherInfo(pkt *xproto.PcapCaputre, size int) *GatherInfo {
	ng := &GatherInfo{
		Packet: pkt,
		Items:  make([]Item, size),
	}

	ng.time = time.Now()
	ng.Items[0].Received = true
	ng.Items[0].LatencyNs = 0

	return ng
}

func (s *GatherInfo) isFull() bool {
	for i := 1; i < len(s.Items); i++ {
		if !s.Items[i].Received {
			return false
		}
	}
	return true
}

func (s *GatherInfo) attachFollow(pkt *xproto.PcapCaputre) {

	idx := pkt.Meta.TracePosIndex

	if s.Items[idx].Received {
		return
	}

	s.Items[idx].LatencyNs = pkt.Meta.TimeStampNs - s.Packet.Meta.TimeStampNs
	s.Items[idx].Received = true
}
