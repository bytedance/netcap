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
package pcap

import (
	"encoding/binary"
	"os"
)

type PcapWriter interface {
	WritePacket(data []byte, info *PacketInfo) error
	Flush()
	Close()
}

type pcapWriterImpl struct {
	file *os.File

	packetMeta [pcapPacketHeaderSize]byte
}

type PacketInfo struct {
	TimeUs int64
	CapLen uint32
	Len    uint32
}

func NewPcapWriter(file *os.File) (PcapWriter, error) {

	s := &pcapWriterImpl{
		file: file,
	}

	err := s.writeFileHeader()
	if err != nil {
		return nil, err
	}

	s.Flush()

	return s, nil
}

func (s *pcapWriterImpl) WritePacket(data []byte, info *PacketInfo) error {
	hdr := &pcapPacketHeader{
		sec:    uint32(info.TimeUs / 1000000),
		us:     uint32(info.TimeUs % 1000000),
		capLen: info.CapLen,
		len:    info.Len,
	}
	buf := s.packetMeta

	binary.LittleEndian.PutUint32(buf[0:4], hdr.sec)
	binary.LittleEndian.PutUint32(buf[4:8], hdr.us)
	binary.LittleEndian.PutUint32(buf[8:12], hdr.capLen)
	binary.LittleEndian.PutUint32(buf[12:16], hdr.len)

	// fmt.Printf("packet header size %d\n", len(buf))
	_, _ = s.file.Write(buf[:])
	_, _ = s.file.Write(data)

	return nil
}

func (s *pcapWriterImpl) Flush() {

	_ = s.file.Sync()
}

func (s *pcapWriterImpl) Close() {

	_ = s.file.Close()
}

func (s *pcapWriterImpl) writeFileHeader() error {
	hdr := &pcapFileHeader{
		magic:        0xA1B2C3D4,
		versionMajor: 2,
		versionMinor: 4,
		thisZone:     0,
		sigFigs:      0,
		snapLen:      0x40000,
		linkType:     1,
	}

	data := make([]byte, pcapFileHeaderSize)

	binary.LittleEndian.PutUint32(data[0:4], hdr.magic)
	binary.LittleEndian.PutUint16(data[4:6], hdr.versionMajor)
	binary.LittleEndian.PutUint16(data[6:8], hdr.versionMinor)

	binary.LittleEndian.PutUint32(data[16:20], hdr.snapLen)
	binary.LittleEndian.PutUint32(data[20:24], hdr.linkType)

	// fmt.Printf("pcap header size %d\n", len(data))

	_, err := s.file.Write(data)
	if err != nil {
		return err
	}
	return nil
}
