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
	"strconv"
	"strings"

	"github.com/bytedance/netcap/pkg/dump/tparser"
)

type RawOption struct {
	Option
}

type rawCodeImpl struct {
	baseCodeImpl

	opt *RawOption
}

func NewRawCode(opt *RawOption) (Operator, error) {
	s := &rawCodeImpl{
		opt: opt,
	}

	err := s.generate()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *rawCodeImpl) generate() error {
	err := s.baseGenerate(&s.opt.Option)
	if err != nil {
		return err
	}

	s.ebpfCode = codeUserH

	marcoCode, err := s.generateRawMarco()
	if err != nil {
		return err
	}

	s.ebpfCode += marcoCode

	s.ebpfCode += s.tcpdumpFilterCode
	s.ebpfCode += s.userFilterCode
	s.ebpfCode += s.userActionCode

	s.ebpfCode += codeCommH
	s.ebpfCode += codeUserCommH

	for i := 0; i < len(s.opt.FunctionDesc); i++ {
		code, info, err := s.generateRawFunctionCode(&s.opt.FunctionDesc[i], i)
		if err != nil {
			return err
		}

		s.ebpfCode += code
		s.traceInfo = append(s.traceInfo, *info)
	}
	return nil
}

func (s *rawCodeImpl) generateRawMarco() (string, error) {
	str := s.commMarcoCode
	return str, nil
}

func (s *rawCodeImpl) generateRawFunctionCode(desc *tparser.FunctionDescribe,
	traceIndex int) (string, *TraceInfo, error) {
	if desc.Prefix == "" {
		return s.generateRawUprobeFunction(desc, traceIndex)

	} else if desc.Prefix == "usdt" {
		return s.generateRawUSDTFunction(desc, traceIndex)

	} else {
		return "", nil, fmt.Errorf("raw trace-function has wrong prefix: %v", desc)
	}
}

func (s *rawCodeImpl) getPrameIndex(desc *tparser.FunctionDescribe) (int, int) {
	param1 := desc.ParamIndex1
	param2 := desc.ParamIndex2

	if param1 == 0 {
		param1 = 1
	}

	if param2 == 0 {
		param2 = param1 + 1
	}

	return param1, param2
}

func (s *rawCodeImpl) generateRawUSDTFunction(desc *tparser.FunctionDescribe,
	traceIndex int) (string, *TraceInfo, error) {

	var code string
	param1, param2 := s.getPrameIndex(desc)

	info := &TraceInfo{
		FunctionDesc: *desc,
	}

	info.EbpfFunctionName = "xcap_usdt_" + desc.FunctionName
	code = codeRawUSDTC

	code = strings.ReplaceAll(code, "USDT", info.EbpfFunctionName)
	code = strings.ReplaceAll(code, "PARAM_INDEX_1", strconv.FormatInt(int64(param1), 10))
	code = strings.ReplaceAll(code, "PARAM_INDEX_2", strconv.FormatInt(int64(param2), 10))

	code = strings.ReplaceAll(code, "TRACE_INDEX", strconv.FormatInt(int64(traceIndex), 10))

	return code, info, nil
}

func (s *rawCodeImpl) generateRawUprobeFunction(desc *tparser.FunctionDescribe,
	traceIndex int) (string, *TraceInfo, error) {

	var code string
	param1, param2 := s.getPrameIndex(desc)

	info := &TraceInfo{
		FunctionDesc: *desc,
	}

	info.EbpfFunctionName = "xcap_uprobe_" + desc.FunctionName
	code = codeRawUprobeC
	code = strings.ReplaceAll(code, "UPROBE", info.EbpfFunctionName)
	code = strings.ReplaceAll(code, "PT_REGS_PARM_DATA", "PT_REGS_PARM"+strconv.FormatInt(int64(param1), 10))
	code = strings.ReplaceAll(code, "PT_REGS_PARM_LEN", "PT_REGS_PARM"+strconv.FormatInt(int64(param2), 10))

	code = strings.ReplaceAll(code, "TRACE_INDEX", strconv.FormatInt(int64(traceIndex), 10))
	return code, info, nil
}
