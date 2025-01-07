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
package dump

import (
	"fmt"
	"os"

	"github.com/bytedance/netcap/pkg/dump/code"
	"github.com/bytedance/netcap/pkg/dump/driver"
)

type MbufOption struct {
	Option

	Pid int
}

type mbufDumpImpl struct {
	dumpBaseImpl
}

func NewMbufDump(opt *MbufOption) (Operator, error) {

	s := &mbufDumpImpl{}

	err := s.baseInit(&opt.Option)
	if err != nil {
		return nil, err
	}

	mbufOpt := &code.MbufOption{
		Option: code.Option{
			TcpdumpExpression: opt.TcpdumpExpression,
			ExtFilterFilePath: opt.ExtFilterFilePath,
			ExtActionFilePath: opt.ExtActionFilePath,
			CaptureMaxSize:    opt.CaptureMaxSize,
			FunctionDesc:      s.parser.Get(),
			IsDumpStack:       false,
		},
	}

	mbufCode, err := code.NewMbufCode(mbufOpt)
	if err != nil {
		return nil, err
	}
	if opt.IsDryRun {
		fmt.Printf("\n%s\n", mbufCode.GetEbpfCode())
		os.Exit(0)
	}

	driverOpt := &driver.MbufOption{
		Option: *driverOption(&opt.Option, mbufCode, false, ""),
		Pid:    opt.Pid,
	}
	s.driver = driver.NewMbufDriver(driverOpt)

	err = s.driver.Init()
	if err != nil {
		return nil, err
	}
	return s, nil
}
