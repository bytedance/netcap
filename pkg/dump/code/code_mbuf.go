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

type MbufOption struct {
	Option
}

type mbufCodeImpl struct {
	baseCodeImpl

	opt *MbufOption
}

func NewMbufCode(opt *MbufOption) (Operator, error) {
	s := &mbufCodeImpl{
		opt: opt,
	}

	err := s.generate()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *mbufCodeImpl) generate() error {
	err := s.baseGenerate(&s.opt.Option)
	if err != nil {
		return err
	}

	s.ebpfCode = codeUserH

	marcoCode, err := s.generateMbufMarco()
	if err != nil {
		return err
	}

	s.ebpfCode += marcoCode

	s.ebpfCode += s.tcpdumpFilterCode
	s.ebpfCode += s.userFilterCode
	s.ebpfCode += s.userActionCode

	s.ebpfCode += codeCommH
	s.ebpfCode += codeUserCommH
	s.ebpfCode += codeMbufC

	for i := 0; i < len(s.opt.FunctionDesc); i++ {
		code, info, err := s.generateMbufFunctionCode(&s.opt.FunctionDesc[i], i)
		if err != nil {
			return err
		}

		s.ebpfCode += code
		s.traceInfo = append(s.traceInfo, *info)
	}

	return nil
}

func (s *mbufCodeImpl) generateMbufMarco() (string, error) {

	str := s.commMarcoCode

	return str, nil
}

func (s *mbufCodeImpl) generateMbufFunctionCode(desc *tparser.FunctionDescribe,
	traceIndex int) (string, *TraceInfo, error) {

	if desc.ParamIndex1 == 0 {
		return "", nil, fmt.Errorf("mbuf trace-function need param %v, such as func@1", desc)
	}

	if desc.Prefix == "" {
		return s.generateMbufUProbeFunction(desc, traceIndex)

	} else if desc.Prefix == "usdt" {
		return s.generateMbufUSDTFunction(desc, traceIndex)

	} else {
		return "", nil, fmt.Errorf("mbuf trace-function has wrong prefix: %v", desc)
	}

}

func (s *mbufCodeImpl) generateMbufUSDTFunction(desc *tparser.FunctionDescribe,
	traceIndex int) (string, *TraceInfo, error) {

	var code string

	info := &TraceInfo{
		FunctionDesc: *desc,
	}

	if desc.ParamIndex2 == 0 {
		info.EbpfFunctionName = "xcap_usdt_" + desc.FunctionName
		code = codeMbufUSDTC
		code = strings.ReplaceAll(code, "USDT", info.EbpfFunctionName)
		code = strings.ReplaceAll(code, "PARAM_INDEX_1", strconv.FormatInt(int64(desc.ParamIndex1), 10))

	} else {
		info.EbpfFunctionName = "xcap_usdt_vec_" + desc.FunctionName
		code = codeMbufUSDTVectorC
		code = strings.ReplaceAll(code, "USDT_VECTOR", info.EbpfFunctionName)
		code = strings.ReplaceAll(code, "PARAM_INDEX_1", strconv.FormatInt(int64(desc.ParamIndex1), 10))
		code = strings.ReplaceAll(code, "PARAM_INDEX_2", strconv.FormatInt(int64(desc.ParamIndex2), 10))
	}
	code = strings.ReplaceAll(code, "TRACE_INDEX", strconv.FormatInt(int64(traceIndex), 10))

	return code, info, nil
}

func (s *mbufCodeImpl) generateMbufUProbeFunction(desc *tparser.FunctionDescribe,
	traceIndex int) (string, *TraceInfo, error) {

	var code string

	info := &TraceInfo{
		FunctionDesc: *desc,
	}

	if desc.ParamIndex2 == 0 {
		info.EbpfFunctionName = "xcap_uprobe_" + desc.FunctionName
		code = codeMbufUProbeC
		code = strings.ReplaceAll(code, "UPROBE", info.EbpfFunctionName)
		code = strings.ReplaceAll(code, "PT_REGS_PARM_MBUF", "PT_REGS_PARM"+strconv.FormatInt(int64(desc.ParamIndex1), 10))

	} else {
		info.EbpfFunctionName = "xcap_uprobe_vec_" + desc.FunctionName
		code = codeMbufUProbeVectorC
		code = strings.ReplaceAll(code, "UPROBE_VECTOR", info.EbpfFunctionName)
		code = strings.ReplaceAll(code, "PT_REGS_PARM_VECTOR_MBUFS", "PT_REGS_PARM"+strconv.FormatInt(int64(desc.ParamIndex1), 10))
		code = strings.ReplaceAll(code, "PT_REGS_PARM_VECTOR_SIZE", "PT_REGS_PARM"+strconv.FormatInt(int64(desc.ParamIndex2), 10))
	}
	code = strings.ReplaceAll(code, "TRACE_INDEX", strconv.FormatInt(int64(traceIndex), 10))

	return code, info, nil
}
