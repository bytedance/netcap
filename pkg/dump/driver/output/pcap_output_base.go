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
	"os"

	"github.com/bytedance/netcap/pkg/dump/xproto"
	"github.com/bytedance/netcap/pkg/pcap"
)

type pcapBase struct {
	baseImpl
	pcapWriter pcap.PcapWriter
	converter  pcapConverter
}

func (s *pcapBase) pcapBuild(opt *Option, outFile *os.File) error {

	s._baseInit(opt)

	p, err := pcap.NewPcapWriter(outFile)
	if err != nil {
		return err
	}

	s.pcapWriter = p
	s.converter = newPcapConverter()

	return nil
}

func (s *pcapBase) pcapClose() {
	s.pcapWriter.Close()
	s._baseClose()
}

func (s *pcapBase) pcapOutput(info *xproto.PcapCaputre, n uint32) {
	pktInfo := &pcap.PacketInfo{
		TimeUs: int64(info.Meta.TimeStampNs / 1000),
		CapLen: uint32(info.Meta.CaptureLength),
		Len:    info.Meta.PacketLength,
	}

	_ = s.pcapWriter.WritePacket(info.PacketData, pktInfo)
	s.pcapWriter.Flush()

	s._baseUserOutput(info.Meta.ExtendUserRet, info.UserExtendData, n)
}
