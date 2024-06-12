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

const (
	pcapFileHeaderSize   = 24
	pcapPacketHeaderSize = 16
)

type pcapFileHeader struct {
	magic        uint32
	versionMajor uint16
	versionMinor uint16
	thisZone     int
	sigFigs      uint32
	snapLen      uint32
	linkType     uint32
}

type pcapPacketHeader struct {
	sec    uint32
	us     uint32
	capLen uint32
	len    uint32
}
