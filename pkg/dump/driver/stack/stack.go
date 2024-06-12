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
package stack

import (
	"fmt"
	"unsafe"

	"github.com/bytedance/netcap/pkg/ksym"
	"github.com/iovisor/gobpf/bcc"
)

type Option struct {
	StackTable *bcc.Table
}

type Operator interface {
	GetStack(id uint32) string
}

type stackImpl struct {
	table   *bcc.Table
	kSymbol ksym.Operator
}

const (
	maxStackDepth = 64
)

type StackData struct {
	IPs [maxStackDepth]uint64
}

func New(opt *Option) (Operator, error) {
	k, err := ksym.New()
	if err != nil {
		return nil, err
	}

	s := &stackImpl{
		table:   opt.StackTable,
		kSymbol: k,
	}

	return s, nil
}

func (s *stackImpl) GetStack(id uint32) string {
	val, err := s.table.GetP(unsafe.Pointer(&id))
	if err != nil {
		return ""
	}
	str := ""
	var stack *StackData = (*StackData)(unsafe.Pointer(val))
	for _, ip := range stack.IPs {
		if ip > 0 {

			item := s.kSymbol.LookUpByAddr(ip)
			if item == nil {
				continue
			}

			str += symbolToString(item, ip)
		}
	}

	return str
}

func symbolToString(item *ksym.Symbol, ip uint64) string {

	str := fmt.Sprintf("    %s+0x%x    %s\n", item.Name, ip-item.Addr, item.Module)

	return str
}
