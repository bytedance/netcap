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
package cmd

import (
	"context"
	"log"

	"github.com/bytedance/netcap/pkg/dump"
	"github.com/spf13/cobra"
)

var (
	dumpTraceFunction    string = ""
	dumpFilterExpression string = ""
	dumpWriteFilePath    string = ""
	dumpWriteFileRotate  uint32 = 0
	dumpTcpdumpFlags     string = "-nn"
	dumpCount            uint32 = 0

	extFilterFile  string = ""
	extActionFile  string = ""
	extOutputColor string = ""

	isDryRun                   bool   = false
	isGatherStatistic          bool   = false
	gatherTimeoutSec           uint32 = 0
	gatherBufferSize           uint32 = 0
	gatherOutputColor          string = ""
	gatherDistinguishByPointer bool   = false
	captureMaxSize             uint32 = 256
)

func dumpCmdLine(c *cobra.Command) {
	c.PersistentFlags().StringVarP(&dumpWriteFilePath, "write-file", "w", dumpWriteFilePath,
		"dump pcap that write to file")
	c.PersistentFlags().Uint32VarP(&dumpWriteFileRotate, "write-file-rotate", "", dumpWriteFileRotate,
		"wirte pcap-file on rotate of count of pkts,it's only work under -w.\nset 0 means disable it. (default 0)")

	c.PersistentFlags().StringVarP(&dumpFilterExpression,
		"expression", "e", dumpFilterExpression, "tcpdump expression")
	c.PersistentFlags().StringVarP(&dumpTraceFunction,
		"function", "f", dumpTraceFunction, "trace function with @param that begin from 1")
	c.PersistentFlags().StringVarP(&dumpTcpdumpFlags,
		"tcpdump-flags", "t", dumpTcpdumpFlags, `tcpdump flags such as "-nnve"`)
	c.PersistentFlags().Uint32VarP(&dumpCount, "count", "c", dumpCount,
		"the count of capture packets")
	c.PersistentFlags().Uint32VarP(&captureMaxSize, "capture-max-size", "", captureMaxSize,
		"the buff size of capture packe, if the pkt_len exceeds this value, \nthen it will be truncated, and it's in range:[128,1514]")

	c.PersistentFlags().StringVarP(&extFilterFile, "ext-filter", "", extFilterFile,
		"user filter ebpf file path")
	c.PersistentFlags().StringVarP(&extActionFile, "ext-action", "", extActionFile,
		"user action ebpf file path")
	c.PersistentFlags().StringVarP(&extOutputColor, "ext-output-color", "", extOutputColor,
		"user output color: red|green|yellow|blue|purple|cyan")

	c.PersistentFlags().BoolVarP(&isDryRun, "dry-run", "", isDryRun, "NOT true run, only dump ebpf C code")

	c.PersistentFlags().BoolVarP(&isGatherStatistic, "gather", "G", isGatherStatistic,
		"gather statistic, only work at multi trace, with this flag then ignore -w")
	c.PersistentFlags().BoolVarP(&gatherDistinguishByPointer, "gather-distinguish-by-pointer", "",
		gatherDistinguishByPointer, "distinguish two skb(mbuf) by pointer, otherwise by contents")
	c.PersistentFlags().Uint32VarP(&gatherTimeoutSec, "gather-timeout", "", gatherTimeoutSec,
		"gather timeout on second")
	c.PersistentFlags().Uint32VarP(&gatherBufferSize, "gather-buffer-size", "", gatherBufferSize,
		"gather buffer size which is between [16, 2048]")
	c.PersistentFlags().StringVarP(&gatherOutputColor, "gather-output-color", "", gatherOutputColor,
		"gather output color: red|green|yellow|blue|purple|cyan")
}

func runDump(dumpOp dump.Operator) {

	err := dumpOp.Run(context.TODO())
	if err != nil {
		log.Fatalf("Dump operator run err: %v", err)
	}
}

func commOption() *dump.Option {
	opt := &dump.Option{
		ExtFilterFilePath:          extFilterFile,
		ExtActionFilePath:          extActionFile,
		ExtOutputColor:             extOutputColor,
		TcpdumpFlags:               dumpTcpdumpFlags,
		TcpdumpExpression:          dumpFilterExpression,
		TraceFunction:              dumpTraceFunction,
		DumpWriteFilePath:          dumpWriteFilePath,
		DumpWriteFileRotate:        dumpWriteFileRotate,
		DumpCount:                  dumpCount,
		CaptureMaxSize:             captureMaxSize,
		IsDryRun:                   isDryRun,
		IsGatherStatistic:          isGatherStatistic,
		GatherTimeoutSec:           gatherTimeoutSec,
		GatherBufferSize:           gatherBufferSize,
		GatherOutputColor:          gatherOutputColor,
		GatherDistinguishByPointer: gatherDistinguishByPointer,
	}

	return opt
}

func commCheck() error {

	if captureMaxSize < 128 {
		captureMaxSize = 128
	} else if captureMaxSize > 1514 {
		captureMaxSize = 1514
	}

	return nil
}
