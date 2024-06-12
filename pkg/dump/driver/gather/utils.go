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

import "github.com/bytedance/netcap/pkg/dump/xproto"

func isSamePacketByContent(p1 *xproto.PcapCaputre, p2 *xproto.PcapCaputre) bool {
	if p1.Meta.CaptureLength != p2.Meta.CaptureLength {
		return false
	}
	if p1.Meta.PacketLength != p2.Meta.PacketLength {
		return false
	}

	for i := 0; i < int(p1.Meta.CaptureLength); i++ {
		if p1.PacketData[i] != p2.PacketData[i] {
			return false
		}
	}

	return true
}
