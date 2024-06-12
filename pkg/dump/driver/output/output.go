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

	"github.com/bytedance/netcap/pkg/dump/driver/gather"
	"github.com/bytedance/netcap/pkg/dump/driver/stack"
	"github.com/bytedance/netcap/pkg/extend"
)

type Option struct {
	UserOutputColor     string
	ExtendOp            extend.Operator
	TcpdumpFlags        string
	WritePcapFilePath   string
	WritePcapFileRotate uint32
	GatherOp            gather.Operator
	GatherOutputColor   string
	StackOp             stack.Operator
	DumpStackColor      string
}

type Operator interface {
	Output(raw []byte, n uint32) (uint32, error)
	OnTick(n uint32) (uint32, error)
	Close()
}

func New(opt *Option) (Operator, error) {

	if opt.StackOp != nil {
		return newOutputTcpdump(opt)
	}

	if opt.GatherOp != nil {
		return newOutputGather(opt)
	}

	if opt.WritePcapFilePath != "" {
		if opt.WritePcapFileRotate == 0 {
			return newOutputFile(opt)
		} else {
			return newOutputFileRotate(opt)
		}
	}

	return newOutputTcpdump(opt)
}

type baseImpl struct {
	extendOper extend.Operator

	userOutputPrefix string
	userOutputSuffix string
}

func (s *baseImpl) _baseInit(opt *Option) {
	s.extendOper = opt.ExtendOp

	s.userOutputPrefix, s.userOutputSuffix = getOutputColor(opt.UserOutputColor)
}

func (s *baseImpl) _baseClose() {

}

func (s *baseImpl) _baseUserOutput(userRet int32, userData []byte, n uint32) {

	if userRet == 0 || s.extendOper == nil {
		return
	}

	str := s.extendOper.Convert(userData)

	fmt.Printf("%s--> No %d's pkt User Action >> %s%s\n", s.userOutputPrefix, n, str, s.userOutputSuffix)
}
