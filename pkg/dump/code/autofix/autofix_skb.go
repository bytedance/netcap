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
package autofix

import (
	"fmt"

	"github.com/bytedance/netcap/pkg/dump/tparser"
	"github.com/bytedance/netcap/pkg/util"
)

type Option struct {
	FunctionDesc []tparser.FunctionDescribe
}

type Operator interface {
	GenerateFixCode() string
}

type autoFixSkbImpl struct {
	opt *Option

	currentKernel *util.KernelVersion
}

func New(opt *Option) Operator {
	s := &autoFixSkbImpl{
		opt:           opt,
		currentKernel: util.GetKernelVersion(),
	}

	return s
}

func (s *autoFixSkbImpl) GenerateFixCode() string {

	str := ""

	if s.currentKernel == nil {
		return str
	}

	for i := 0; i < len(s.opt.FunctionDesc); i++ {
		desc := &s.opt.FunctionDesc[i]

		if desc.Prefix == "" {
			str += s.fixKprobe(desc, i)
		}
	}

	return str
}

func (s *autoFixSkbImpl) generateUseSkbData(traceIndex int, offset int32) string {

	fstr :=
		`if (trace_index == %d) {
	data = skb_data + %d;
}`

	return fmt.Sprintf(fstr, traceIndex, offset)
}

func (s *autoFixSkbImpl) fixKprobe(desc *tparser.FunctionDescribe, traceIndex int) string {

	str := ""

	if desc.FunctionName == "__dev_direct_xmit" || desc.FunctionName == "xsk_destruct_skb" {
		if s.currentKernel.Major >= 5 && s.currentKernel.Minor >= 10 {
			str += s.generateUseSkbData(traceIndex, 0)
		}
	}

	return str
}
