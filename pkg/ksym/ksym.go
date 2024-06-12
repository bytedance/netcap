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
package ksym

import (
	"bufio"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Symbol struct {
	Addr   uint64
	Name   string
	Module string
}

type Operator interface {
	LookUpByAddr(addr uint64) *Symbol
}

type operImpl struct {
	symbols []Symbol
}

type bySAddr []Symbol

func (a bySAddr) Len() int           { return len(a) }
func (a bySAddr) Less(i, j int) bool { return a[i].Addr < a[j].Addr }
func (a bySAddr) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func New() (Operator, error) {

	s := &operImpl{}

	err := s.build()
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *operImpl) LookUpByAddr(addr uint64) *Symbol {
	total := len(s.symbols)
	i, j := 0, total
	for i < j {
		h := int(uint(i+j) >> 1)
		if s.symbols[h].Addr <= addr {
			if h+1 < total && s.symbols[h+1].Addr > addr {
				return &s.symbols[h]
			}
			i = h + 1
		} else {
			j = h
		}
	}
	return nil
}

func (s *operImpl) build() error {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.Split(scanner.Text(), " ")
		name := line[2]
		module := ""
		addr, err := strconv.ParseUint(line[0], 16, 64)
		if err != nil {
			return err
		}
		arr := strings.Split(name, "\t")
		if len(arr) >= 2 {
			name = arr[0]
			module = arr[1]
		}
		sym := Symbol{
			Addr:   addr,
			Name:   name,
			Module: module,
		}
		s.symbols = append(s.symbols, sym)
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	sort.Sort(bySAddr(s.symbols))
	return nil
}
