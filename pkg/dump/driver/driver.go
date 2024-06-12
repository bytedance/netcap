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
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bytedance/netcap/pkg/dump/code"
	"github.com/bytedance/netcap/pkg/dump/driver/gather"
	"github.com/bytedance/netcap/pkg/dump/driver/output"
	"github.com/bytedance/netcap/pkg/dump/driver/stack"
	"github.com/bytedance/netcap/pkg/dump/xproto"
	"github.com/bytedance/netcap/pkg/extend"
	"github.com/iovisor/gobpf/bcc"
)

const (
	perfChannelSize = 1024
)

type Option struct {
	UserOuputColor             string
	DumpWriteFilePath          string
	DumpWriteFileRotate        uint32
	TcpdumpFlags               string
	DumpCount                  uint32
	Code                       code.Operator
	IsGatherStatistic          bool
	GatherTimeoutSec           uint32
	GatherBufferSize           uint32
	GatherOutputColor          string
	GatherDistinguishByPointer bool

	IsDumpStack    bool
	DumpStackColor string
}

type Operator interface {
	Init() error
	Run(ctx context.Context) error
}

type driverBaseImpl struct {
	m            *bcc.Module
	gather       gather.Operator
	outputDriver output.Operator
	extendOp     extend.Operator
	perfMap      *bcc.PerfMap
	perfChannel  chan []byte
	tickChannel  chan int
	maxDumpCount uint32

	dumpCount uint32
}

func (s *driverBaseImpl) Run(_ context.Context) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go s.loop()
	go s.tick()

	s.perfMap.Start()
	<-sig
	fmt.Printf("\n")
	s.perfMap.Stop()

	if s.gather != nil {
		s.gather.Close()
	}
	s.outputDriver.Close()
	if s.extendOp != nil {
		s.extendOp.Close()
	}
	return nil
}

func (s *driverBaseImpl) tick() {

	for {
		time.Sleep(time.Duration(10) * time.Millisecond)
		s.tickChannel <- 1
	}
}

func (s *driverBaseImpl) loop() {

	for {
		select {

		case data, ok := <-s.perfChannel:
			if !ok {
				os.Exit(0)
			}
			s.dumpCount, _ = s.outputDriver.Output(data, s.dumpCount)

		case <-s.tickChannel:
			s.dumpCount, _ = s.outputDriver.OnTick(s.dumpCount)
		}

		if s.maxDumpCount != 0 {
			if s.dumpCount >= s.maxDumpCount {
				os.Exit(0)
			}
		}
	}
}

func (s *driverBaseImpl) _baseNewStackOperator(opt *Option, isDumpStack bool) (stack.Operator, error) {

	if !isDumpStack {
		return nil, nil
	}

	stackTable := bcc.NewTable(s.m.TableId(xproto.StackTableName), s.m)
	if stackTable == nil {
		return nil, fmt.Errorf("create stack-table error")
	}

	stackOpt := &stack.Option{
		StackTable: stackTable,
	}

	return stack.New(stackOpt)
}

func (s *driverBaseImpl) _baseNewOutput(opt *Option) (output.Operator, error) {

	stackOp, err := s._baseNewStackOperator(opt, opt.IsDumpStack)
	if err != nil {
		return nil, err
	}

	outputOpt := &output.Option{
		ExtendOp:            s.extendOp,
		UserOutputColor:     opt.UserOuputColor,
		TcpdumpFlags:        opt.TcpdumpFlags,
		WritePcapFilePath:   opt.DumpWriteFilePath,
		WritePcapFileRotate: opt.DumpWriteFileRotate,
		GatherOp:            s.gather,
		GatherOutputColor:   opt.GatherOutputColor,
		StackOp:             stackOp,
		DumpStackColor:      opt.DumpStackColor,
	}

	return output.New(outputOpt)

}

func (s *driverBaseImpl) baseInit(opt *Option) error {

	s.dumpCount = 0
	s.maxDumpCount = opt.DumpCount
	s.perfChannel = make(chan []byte, perfChannelSize)
	s.tickChannel = make(chan int)
	s.extendOp = extend.New(&extend.Option{UserActionCode: opt.Code.GetUserActionCode()})

	var err error

	if opt.IsGatherStatistic {
		s.gather, err = gather.New(&gather.Option{
			Code:                       opt.Code,
			GatherTimeoutSec:           opt.GatherTimeoutSec,
			GatherBufferSize:           opt.GatherBufferSize,
			GatherDistinguishByPointer: opt.GatherDistinguishByPointer,
		})
		if err != nil {
			return err
		}
	}

	s.outputDriver, err = s._baseNewOutput(opt)
	if err != nil {
		return err
	}

	err = s._baseEbpfPerfTable()
	if err != nil {
		return err
	}

	return nil
}

func (s *driverBaseImpl) _baseEbpfPerfTable() error {

	table := bcc.NewTable(s.m.TableId(xproto.PerfTableName), s.m)

	perfMap, err := bcc.InitPerfMap(table, s.perfChannel, nil)
	if err != nil {
		log.Fatalf("init perf map err: %v", err)
		return err
	}
	s.perfMap = perfMap

	return nil
}
