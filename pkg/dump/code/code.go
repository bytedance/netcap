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
package code

import (
	"fmt"
	"os"

	"github.com/bytedance/netcap/pkg/cbpf_filter"
	"github.com/bytedance/netcap/pkg/dump/tparser"
	"github.com/google/gopacket/layers"
)

type TraceInfo struct {
	EbpfFunctionName string
	FunctionDesc     tparser.FunctionDescribe
}

type Operator interface {
	GetEbpfCode() string
	GetComplieFlags() []string
	GetUserActionCode() string

	GetTraceInfo() []TraceInfo
}

type Option struct {
	ExtFilterFilePath string
	ExtActionFilePath string
	TcpdumpExpression string
	CaptureMaxSize    uint32

	IsDumpStack bool

	FunctionDesc []tparser.FunctionDescribe
}

type baseCodeImpl struct {
	ebpfCode          string
	tcpdumpFilterCode string
	userFilterCode    string
	userActionCode    string
	commMarcoCode     string

	compileFlags []string
	traceInfo    []TraceInfo
}

func (s *baseCodeImpl) GetEbpfCode() string {
	return s.ebpfCode
}

func (s *baseCodeImpl) GetUserActionCode() string {
	return s.userActionCode
}

func (s *baseCodeImpl) GetComplieFlags() []string {
	return s.compileFlags
}

func (s *baseCodeImpl) GetTraceInfo() []TraceInfo {
	return s.traceInfo
}

func (s *baseCodeImpl) _generateCbpfFilter(tcpdumpExpression string) (string, error) {
	f, err := cbpf_filter.New(tcpdumpExpression, layers.LinkTypeEthernet)
	if err != nil {
		return "", err
	}
	return f.ToC()
}

func _readFile(path string) (string, error) {
	content, err := os.ReadFile(path)

	if err != nil {
		return "", err
	}

	return string(content), nil
}

func (s *baseCodeImpl) baseGenerate(opt *Option) error {

	var err error

	if opt.TcpdumpExpression != "" {
		s.tcpdumpFilterCode, err = s._generateCbpfFilter(opt.TcpdumpExpression)
		if err != nil {
			return err
		}
		s.tcpdumpFilterCode += "\n"
		s.compileFlags = append(s.compileFlags, "-DENABLE_FILTER")
	} else {
		s.tcpdumpFilterCode = ""
	}

	if opt.ExtFilterFilePath != "" {
		s.userFilterCode, err = _readFile(opt.ExtFilterFilePath)
		if err != nil {
			return err
		}
		s.compileFlags = append(s.compileFlags, "-DENABLE_EXT_FILTER")
	} else {
		s.userFilterCode = ""
	}

	if opt.ExtActionFilePath != "" {
		s.userActionCode, err = _readFile(opt.ExtActionFilePath)
		if err != nil {
			return err
		}
		s.compileFlags = append(s.compileFlags, "-DENABLE_EXT_ACTION")
	} else {
		s.userActionCode = ""
	}

	if opt.IsDumpStack {
		s.compileFlags = append(s.compileFlags, "-DSTACK_DUMP")
	}

	s.commMarcoCode = fmt.Sprintf("#define CAPTURE_LEN  %d\n\n", opt.CaptureMaxSize)

	return nil
}
