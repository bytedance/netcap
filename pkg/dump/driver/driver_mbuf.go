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

	"github.com/bytedance/netcap/pkg/dump/code"
	"github.com/iovisor/gobpf/bcc"
)

type MbufOption struct {
	Option

	Pid int
}

type mbufDriverImpl struct {
	driverBaseImpl

	opt *MbufOption

	ebpfCode string
}

func NewMbufDriver(opt *MbufOption) Operator {
	s := &mbufDriverImpl{
		opt: opt,
	}

	return s
}

func (s *mbufDriverImpl) Init() error {

	err := s.buildMbuf()
	if err != nil {
		return err
	}

	err = s.baseInit(&s.opt.Option)
	if err != nil {
		return err
	}

	return nil
}

func (s *mbufDriverImpl) buildMbuf() error {

	s.ebpfCode = s.opt.Code.GetEbpfCode()
	infos := s.opt.Code.GetTraceInfo()

	s.m = bcc.NewModule(s.ebpfCode, s.opt.Code.GetComplieFlags())
	if s.m == nil {
		return fmt.Errorf("bcc.NewModule error")
	}

	return s.attachTrace(infos)
}

func (s *mbufDriverImpl) attachUProbe(info *code.TraceInfo) error {

	prog, err := s.m.LoadUprobe(info.EbpfFunctionName)
	if err != nil {
		return err
	}
	err = s.m.AttachUprobe(fmt.Sprintf("/proc/%v/exe", s.opt.Pid), info.FunctionDesc.FunctionName, prog, s.opt.Pid)
	if err != nil {
		return err
	}
	return nil
}

func (s *mbufDriverImpl) attachTrace(infos []code.TraceInfo) error {
	var err error
	for i := 0; i < len(infos); i++ {
		if infos[i].FunctionDesc.Prefix == "usdt" {
			continue
		}
		err = s.attachUProbe(&infos[i])
		if err != nil {
			return err
		}
	}

	return nil
}
