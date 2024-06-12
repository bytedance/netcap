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

type RawOption struct {
	Option

	Pid int
}

type rawDumpImpl struct {
	dumpBaseImpl
}

func NewRawDump(opt *RawOption) (Operator, error) {

	s := &rawDumpImpl{}

	err := s.baseInit(&opt.Option)
	if err != nil {
		return nil, err
	}

	rawOpt := &code.RawOption{
		Option: code.Option{
			TcpdumpExpression:  opt.TcpdumpExpression,
			UserFilterFilePath: opt.UserFilterFilePath,
			UserActionFilePath: opt.UserActionFilePath,
			CaptureMaxSize:     opt.CaptureMaxSize,
			FunctionDesc:       s.parser.Get(),
			IsDumpStack:        false,
		},
	}

	rawCode, err := code.NewRawCode(rawOpt)
	if err != nil {
		return nil, err
	}
	if opt.IsDryRun {
		fmt.Printf("\n%s\n", rawCode.GetEbpfCode())
		os.Exit(0)
	}

	driverOpt := &driver.MbufOption{
		Option: *driverOption(&opt.Option, rawCode, false, ""),
		Pid:    opt.Pid,
	}
	s.driver = driver.NewMbufDriver(driverOpt)

	err = s.driver.Init()
	if err != nil {
		return nil, err
	}
	return s, nil
}
