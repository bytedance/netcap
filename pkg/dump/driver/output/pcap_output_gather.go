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
	"os"

	"github.com/bytedance/netcap/pkg/dump/driver/gather"
)

type outputGather struct {
	pcapBase

	gatherOp gather.Operator
	proxy    tcpdumpProxy
	prefix   string
	suffix   string
}

func newOutputGather(opt *Option) (Operator, error) {
	s := &outputGather{
		gatherOp: opt.GatherOp,
		proxy:    newTcpdumpProxy(os.Stdout, opt.TcpdumpFlags),
	}

	s.prefix, s.suffix = getOutputColor(opt.GatherOutputColor)

	err := s.pcapBuild(opt, s.proxy.GetInput())
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *outputGather) Output(raw []byte, n uint32) (uint32, error) {

	info, err := s.converter.Convert(raw)
	if err != nil {
		return n, err
	}

	g := s.gatherOp.Feed(info)

	if g == nil {
		return n, nil
	}

	return s.outputGatherInfo(g, n)
}

func (s *outputGather) OnTick(n uint32) (uint32, error) {

	g := s.gatherOp.Get()

	if g == nil {
		return n, nil
	}

	return s.outputGatherInfo(g, n)
}

func (s *outputGather) outputGatherInfo(info *gather.GatherInfo, n uint32) (uint32, error) {
	s.pcapOutput(info.Packet, n)

	str := s.gatherOp.ToString(info, n)

	fmt.Printf("%s%s%s", s.prefix, str, s.suffix)

	return n + 1, nil
}

func (s *outputGather) Close() {
	s.pcapClose()
}
