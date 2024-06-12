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
package output

import (
	"fmt"
	"unsafe"

	"github.com/bytedance/netcap/pkg/dump/xproto"
	"github.com/bytedance/netcap/pkg/gmt"
)

type pcapConverter interface {
	Convert(raw []byte) (*xproto.PcapCaputre, error)
}

type captureOperatorImpl struct {
	gmtOp gmt.Operator
}

func newPcapConverter() pcapConverter {
	s := &captureOperatorImpl{
		gmtOp: gmt.NewGMT(),
	}

	return s
}

func (s *captureOperatorImpl) Convert(raw []byte) (*xproto.PcapCaputre, error) {

	var pkt *xproto.PacketMeta = *(**xproto.PacketMeta)(unsafe.Pointer(&raw))

	totalSize := int(pkt.BufferOffset) + int(pkt.CaptureLength)

	if totalSize > len(raw) {
		return nil, fmt.Errorf("size error need %d but only %d", totalSize, len(raw))
	}

	xc := &xproto.PcapCaputre{
		Meta:           *pkt,
		UserExtendData: raw[pkt.ExtendOffset:pkt.BufferOffset],
		PacketData:     raw[pkt.BufferOffset:totalSize],
	}

	xc.Meta.TimeStampNs = s.gmtOp.MonotonicToGMT(xc.Meta.TimeStampNs)

	return xc, nil
}
