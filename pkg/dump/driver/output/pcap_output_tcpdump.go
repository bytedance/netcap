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

	"github.com/bytedance/netcap/pkg/dump/driver/stack"
)

type outputTcpdump struct {
	pcapBase

	proxy             tcpdumpProxy
	stackOp           stack.Operator
	stackOutputPrefix string
	stackOutputSuffix string
}

func newOutputTcpdump(opt *Option) (Operator, error) {

	s := &outputTcpdump{
		proxy:   newTcpdumpProxy(os.Stdout, opt.TcpdumpFlags),
		stackOp: opt.StackOp,
	}

	err := s.pcapBuild(opt, s.proxy.GetInput())
	if err != nil {
		return nil, err
	}

	s.stackOutputPrefix, s.stackOutputSuffix = getOutputColor(opt.DumpStackColor)

	return s, nil
}

func (s *outputTcpdump) Output(raw []byte, n uint32) (uint32, error) {

	info, err := s.converter.Convert(raw)
	if err != nil {
		return n + 1, err
	}

	s.pcapOutput(info, n)

	s.stackOutput(n, info.Meta.StackID)

	return n + 1, nil
}

func (s *outputTcpdump) OnTick(n uint32) (uint32, error) {
	return n, nil
}

func (s *outputTcpdump) Close() {
	s.pcapClose()
}

func (s *outputTcpdump) stackOutput(n uint32, stackID uint32) {

	if s.stackOp == nil {
		return
	}

	fmt.Printf("%s--> No %d's packet's kstack: \n%s%s\n", s.stackOutputPrefix, n,
		s.stackOp.GetStack(stackID), s.stackOutputSuffix)
}
