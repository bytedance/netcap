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
package driver

import (
	"fmt"
	"log"

	"github.com/bytedance/netcap/pkg/dump/code"
	"github.com/iovisor/gobpf/bcc"
)

type SkbOption struct {
	Option
}

type skbDriverImpl struct {
	driverBaseImpl

	opt *SkbOption
}

func NewSkbDriver(opt *SkbOption) Operator {
	s := &skbDriverImpl{
		opt: opt,
	}

	return s
}

func (s *skbDriverImpl) attachSkbKprobe(info *code.TraceInfo) error {
	prog, err := s.m.LoadKprobe(info.EbpfFunctionName)
	if err != nil {
		return err
	}
	err = s.m.AttachKprobe(info.FunctionDesc.FunctionName, prog, -1)
	if err != nil {
		log.Fatalf("attach kprobe %s err: %v", info.FunctionDesc.FunctionName, err)
		return err
	}
	return nil
}

func (s *skbDriverImpl) attachSkbTracepoint(info *code.TraceInfo) error {
	prog, err := s.m.LoadTracepoint(info.EbpfFunctionName)
	if err != nil {
		return err
	}

	err = s.m.AttachTracepoint(info.FunctionDesc.FunctionName, prog)
	if err != nil {
		log.Fatalf("attach tracepoint %s prog %d err: %v", info.FunctionDesc.FunctionName, prog, err)
		return err
	}
	return nil
}

func (s *skbDriverImpl) attachSkbFunctions() error {

	infos := s.opt.Code.GetTraceInfo()

	for i := 0; i < len(infos); i++ {
		prefix := infos[i].FunctionDesc.Prefix
		var err error

		if prefix == "" {
			err = s.attachSkbKprobe(&infos[i])
		} else if prefix == "tp" || prefix == "tracepoint" {
			err = s.attachSkbTracepoint(&infos[i])
		} else {
			err = fmt.Errorf("skb not support prefix: %s", prefix)
		}

		if err != nil {
			return err
		}
	}

	return nil
}

func (s *skbDriverImpl) Init() error {

	s.m = bcc.NewModule(s.opt.Code.GetEbpfCode(), s.opt.Code.GetComplieFlags())

	if s.m == nil {
		return fmt.Errorf("bcc.NewModule error")
	}

	err := s.attachSkbFunctions()
	if err != nil {
		return err
	}

	err = s.baseInit(&s.opt.Option)
	if err != nil {
		return err
	}

	return nil
}
