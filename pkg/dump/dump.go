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
	"context"
	"fmt"

	"github.com/bytedance/netcap/pkg/dump/code"
	"github.com/bytedance/netcap/pkg/dump/driver"
	"github.com/bytedance/netcap/pkg/dump/tparser"
)

type Operator interface {
	Run(ctx context.Context) error
}

type Option struct {
	UserFilterFilePath  string
	UserActionFilePath  string
	UserOutputColor     string
	TcpdumpFlags        string
	TcpdumpExpression   string
	TraceFunction       string
	DumpWriteFilePath   string
	DumpWriteFileRotate uint32

	DumpCount      uint32
	CaptureMaxSize uint32

	IsDryRun                   bool
	IsGatherStatistic          bool
	GatherTimeoutSec           uint32
	GatherBufferSize           uint32
	GatherOutputColor          string
	GatherDistinguishByPointer bool
}

type dumpBaseImpl struct {
	driver driver.Operator
	parser tparser.Operator
}

func (s *dumpBaseImpl) Run(ctx context.Context) error {
	return s.driver.Run(ctx)
}

func (s *dumpBaseImpl) baseInit(opt *Option) error {
	s.parser = tparser.New()

	err := s.parser.Parse(opt.TraceFunction)
	if err != nil {
		return err
	}

	if opt.IsGatherStatistic {
		if len(s.parser.Get()) <= 1 {
			return fmt.Errorf("--statistic only work in multi trace")
		}
	}

	return nil
}

func driverOption(opt *Option, c code.Operator, isStackDump bool, stackDumpColor string) *driver.Option {
	drverOp := &driver.Option{
		UserOuputColor:             opt.UserOutputColor,
		DumpWriteFilePath:          opt.DumpWriteFilePath,
		DumpWriteFileRotate:        opt.DumpWriteFileRotate,
		TcpdumpFlags:               opt.TcpdumpFlags,
		DumpCount:                  opt.DumpCount,
		Code:                       c,
		IsGatherStatistic:          opt.IsGatherStatistic,
		GatherTimeoutSec:           opt.GatherTimeoutSec,
		GatherBufferSize:           opt.GatherBufferSize,
		GatherOutputColor:          opt.GatherOutputColor,
		GatherDistinguishByPointer: opt.GatherDistinguishByPointer,
		IsDumpStack:                isStackDump,
		DumpStackColor:             stackDumpColor,
	}

	return drverOp
}
