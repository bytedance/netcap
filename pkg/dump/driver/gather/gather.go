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
	"fmt"

	"github.com/bytedance/netcap/pkg/dump/code"
	"github.com/bytedance/netcap/pkg/dump/xproto"
)

type Option struct {
	Code                       code.Operator
	GatherTimeoutSec           uint32
	GatherBufferSize           uint32
	GatherDistinguishByPointer bool
}

type Operator interface {
	Feed(pkt *xproto.PcapCaputre) *GatherInfo
	Get() *GatherInfo
	ToString(g *GatherInfo, n uint32) string
	Close()
}

type gatherImpl struct {
	traceInfos []code.TraceInfo
	c          container
}

func New(opt *Option) (Operator, error) {
	s := &gatherImpl{
		traceInfos: opt.Code.GetTraceInfo(),
		c:          newContainer(opt),
	}

	return s, nil
}

func (s *gatherImpl) feed(pkt *xproto.PcapCaputre) *GatherInfo {
	g := s.c.LookUp(pkt)

	if pkt.Meta.TracePosIndex == 0 {
		// head packet
		if g != nil {
			_ = s.c.Del(g)
		}
		ng := s.newGather(pkt)
		_ = s.c.Add(ng)
		return g
	}

	// follow packet
	if g != nil {
		g.attachFollow(pkt)
		if g.isFull() {
			_ = s.c.Del(g)
			return g
		}
	}
	return nil
}

func (s *gatherImpl) Feed(pkt *xproto.PcapCaputre) *GatherInfo {

	if int(pkt.Meta.TracePosIndex) >= len(s.traceInfos) {
		return nil
	}

	g := s.feed(pkt)

	if g == nil {
		return s.c.GetTimeout()
	}

	return g
}

func (s *gatherImpl) Get() *GatherInfo {
	return s.c.GetTimeout()
}

func (s *gatherImpl) Close() {
	s.c.Close()
}

func (s *gatherImpl) newGather(pkt *xproto.PcapCaputre) *GatherInfo {
	return newGatherInfo(pkt, len(s.traceInfos))
}

func (s *gatherImpl) ToString(g *GatherInfo, n uint32) string {

	titleFuncName := s.getFunctionName(int(g.Packet.Meta.TracePosIndex))
	str := s.getTitleStr(titleFuncName, n)

	for i := 1; i < len(g.Items); i++ {
		str += s.getFollowStr(i, &g.Items[i], titleFuncName)
	}

	return str
}

func (s *gatherImpl) getFunctionName(tracePosIndex int) string {
	t := s.traceInfos[tracePosIndex]
	var funcName string

	if t.FunctionDesc.Prefix != "" {
		funcName = t.FunctionDesc.Prefix + ":" + t.FunctionDesc.FunctionName
	} else {
		funcName = t.FunctionDesc.FunctionName
	}
	return funcName
}

func (s *gatherImpl) getTitleStr(titleFunc string, n uint32) string {
	return fmt.Sprintf("+-- No'%d packet received in %s\n", n, titleFunc)
}

func (s *gatherImpl) getFollowStr(index int, item *Item, titleFunc string) string {

	name := s.getFunctionName(index)

	if item.Received {
		return fmt.Sprintf("|   * %d (ns) later received in %s \n", item.LatencyNs, name)
	} else {
		return fmt.Sprintf("|   * NOT received at %s\n", name)
	}

}
