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
	"net"
	"strconv"
	"strings"

	"github.com/bytedance/netcap/pkg/dump/code/autofix"
	"github.com/bytedance/netcap/pkg/dump/tparser"
)

type SkbOption struct {
	Option

	Interface     string
	IsFakeHdr     bool
	IsUseSkbData  bool
	SkbDataOffset int32
}

type skbCodeImpl struct {
	baseCodeImpl

	opt *SkbOption

	fixSkb autofix.Operator
}

func NewSkbCode(opt *SkbOption) (Operator, error) {

	if opt.IsFakeHdr {
		opt.IsUseSkbData = false
	}

	s := &skbCodeImpl{
		opt: opt,
		fixSkb: autofix.New(&autofix.Option{
			FunctionDesc: opt.FunctionDesc,
		}),
	}

	err := s.generate()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *skbCodeImpl) generate() error {

	err := s.baseGenerate(&s.opt.Option)
	if err != nil {
		return err
	}

	s.ebpfCode = codeSkbH

	marcoCode, err := s.generateSkbMarco(s.opt)
	if err != nil {
		return err
	}

	s.ebpfCode += marcoCode

	s.ebpfCode += s.tcpdumpFilterCode
	s.ebpfCode += s.userFilterCode
	s.ebpfCode += s.userActionCode

	s.ebpfCode += codeCommH
	s.ebpfCode += codeSkbCommC

	if s.opt.IsFakeHdr {
		s.ebpfCode += codeSkbFakeC
	} else {
		s.ebpfCode += codeSkbC
	}

	for i := 0; i < len(s.opt.FunctionDesc); i++ {
		code, info, err := s.generateSkbFunctionCode(&s.opt.FunctionDesc[i], i)
		if err != nil {
			return err
		}

		s.ebpfCode += code
		s.traceInfo = append(s.traceInfo, *info)
	}

	return s.fixSkbCode()
}

func _getNetIfindex(devName string) (int, error) {
	iface, err := net.InterfaceByName(devName)
	if err != nil {
		return 0, err
	}

	ifindex := iface.Index
	return ifindex, nil
}

func (s *skbCodeImpl) generateSkbMarco(opt *SkbOption) (string, error) {

	str := s.commMarcoCode

	if opt.Interface != "" && opt.Interface != "any" {

		ifIndex, err := _getNetIfindex(opt.Interface)
		if err != nil {
			fmt.Printf("-i Input error: %s\n", opt.Interface)
			return "", err
		}

		str += fmt.Sprintf("#define CONFIG_IFINDEX %d\n", ifIndex)
	}

	if opt.IsFakeHdr {
		str += "#define CONFIG_ENABLE_FAKEHDR \n"
	}

	return str, nil
}

func (s *skbCodeImpl) generateSkbFunctionCode(desc *tparser.FunctionDescribe, traceIndex int) (string, *TraceInfo, error) {

	if desc.Prefix == "" {
		return s.generateSkbKrpbe(desc, traceIndex)
	} else if desc.Prefix == "tp" || desc.Prefix == "tracepoint" {
		return s.generateSkbTracepoint(desc, traceIndex)
	} else {
		return "", nil, fmt.Errorf("skb trace-function not support prex: %v", desc)
	}
}

func (s *skbCodeImpl) generateSkbKrpbe(desc *tparser.FunctionDescribe, traceIndex int) (string, *TraceInfo, error) {

	if desc.ParamIndex1 == 0 {
		return "", nil, fmt.Errorf("skb trace-function kprobe need param %v, such as func@1", desc)
	}

	if desc.ParamIndex2 == desc.ParamIndex1 {
		return "", nil, fmt.Errorf("skb trace-function kprobe ext-param-index error equal to skb-param-index: %v", desc)
	}

	info := &TraceInfo{
		EbpfFunctionName: "xcap_kprobe_" + strings.ReplaceAll(desc.FunctionName, ".", "_"),
		FunctionDesc:     *desc,
	}

	code := codeSkbKprobeC
	code = strings.ReplaceAll(code, "SKB_KPROBE", info.EbpfFunctionName)
	code = strings.ReplaceAll(code, "SKB_REGS_PARAM_X", "PT_REGS_PARM"+strconv.FormatInt(int64(desc.ParamIndex1), 10))
	code = strings.ReplaceAll(code, "TRACE_INDEX", strconv.FormatInt(int64(traceIndex), 10))

	if desc.ParamIndex2 != 0 {
		code = strings.ReplaceAll(code, "SKB_SET_EXT_PARAM",
			"ext = (void*)PT_REGS_PARM"+strconv.FormatInt(int64(desc.ParamIndex2), 10)+"(ctx);")
	} else {
		code = strings.ReplaceAll(code, "SKB_SET_EXT_PARAM", "")
	}

	return code, info, nil
}

func (s *skbCodeImpl) generateSkbTracepoint(desc *tparser.FunctionDescribe, traceIndex int) (string, *TraceInfo, error) {
	if desc.ParamIndex1 != 0 {
		return "", nil, fmt.Errorf("skb trace-function tracepoint does'nt need param by @: %v", desc)
	}

	arr := strings.SplitN(desc.FunctionName, ":", 2)
	if len(arr) != 2 {
		return "", nil, fmt.Errorf("skb trace-function tracepoint format error: %v", desc)
	}

	offset, err := getSkbOffsetOnTracepoint(arr[0], arr[1])
	if err != nil {
		return "", nil, err
	}

	info := &TraceInfo{
		EbpfFunctionName: "xcap_tp_" + arr[1],
		FunctionDesc:     *desc,
	}

	code := codeSkbTracepointC
	code = strings.ReplaceAll(code, "SKB_TRACEPOINT", info.EbpfFunctionName)
	code = strings.ReplaceAll(code, "TP_STRUCT", arr[1])
	code = strings.ReplaceAll(code, "TP_SKB_OFFSET", strconv.FormatInt(int64(offset), 10))
	code = strings.ReplaceAll(code, "TRACE_INDEX", strconv.FormatInt(int64(traceIndex), 10))

	return code, info, nil
}

func (s *skbCodeImpl) fixSkbCode() error {

	str := ""

	if s.opt.IsUseSkbData {
		str = fmt.Sprintf("data = skb_data + %d;", s.opt.SkbDataOffset)

	} else {
		str = s.fixSkb.GenerateFixCode()
	}

	s.ebpfCode = strings.ReplaceAll(s.ebpfCode, "XCAP_FIX_DATA", str)

	return nil
}
