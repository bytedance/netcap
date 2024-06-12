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

const (
	minCache          = 16
	maxCache          = 2048
	defaultCache      = 64
	defaultTimeoutSec = 2
)

type container interface {
	LookUp(pkt *xproto.PcapCaputre) *GatherInfo

	Add(g *GatherInfo) error
	Del(g *GatherInfo) error

	GetTimeout() *GatherInfo

	Close()
}

type containerImpl struct {
	pktList              *list.List
	timeOutSec           uint32
	cacheSize            int
	distinguishByPointer bool
}

func newContainer(opt *Option) container {
	s := &containerImpl{
		pktList:              list.New(),
		timeOutSec:           opt.GatherTimeoutSec,
		cacheSize:            int(opt.GatherBufferSize),
		distinguishByPointer: opt.GatherDistinguishByPointer,
	}
	if s.cacheSize < minCache || s.cacheSize > maxCache {
		s.cacheSize = defaultCache
	}
	if s.timeOutSec <= 0 {
		s.timeOutSec = defaultTimeoutSec
	}

	return s
}

func (s *containerImpl) isSamePacket(p1 *xproto.PcapCaputre, p2 *xproto.PcapCaputre) bool {

	if s.distinguishByPointer {
		return p1.Meta.Ptr == p2.Meta.Ptr
	}

	return isSamePacketByContent(p1, p2)
}

func (s *containerImpl) LookUp(pkt *xproto.PcapCaputre) *GatherInfo {
	for e := s.pktList.Front(); e != nil; e = e.Next() {

		g, ok := e.Value.(*GatherInfo)
		if !ok {
			continue
		}

		if s.isSamePacket(pkt, g.Packet) {
			return g
		}
	}

	return nil
}

func (s *containerImpl) Add(g *GatherInfo) error {

	e := s.pktList.PushBack(g)
	g.elemet = e

	return nil
}

func (s *containerImpl) Del(g *GatherInfo) error {
	s.pktList.Remove(g.elemet)
	return nil
}

func (s *containerImpl) GetTimeout() *GatherInfo {
	e := s.pktList.Front()

	if e == nil {
		return nil
	}
	g, ok := e.Value.(*GatherInfo)
	if !ok {
		return nil
	}

	if s.isTimeout(g) {
		_ = s.Del(g)
		return g
	}
	return nil
}

func (s *containerImpl) Close() {

}

func (s *containerImpl) isTimeout(g *GatherInfo) bool {

	if s.pktList.Len() >= s.cacheSize {
		return true
	}

	now := time.Now()

	duration := now.Sub(g.time)

	return duration >= time.Duration(s.timeOutSec)*time.Second
}
