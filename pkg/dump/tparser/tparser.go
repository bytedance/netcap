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
package tparser

import (
	"fmt"
	"strconv"
	"strings"
)

type FunctionDescribe struct {
	Prefix       string
	FunctionName string
	ParamIndex1  int
	ParamIndex2  int
}

type Operator interface {
	Parse(str string) error
	Get() []FunctionDescribe
}

type tparserImpl struct {
	funcDesc []FunctionDescribe
}

func New() Operator {
	s := &tparserImpl{}

	return s
}

func (s *tparserImpl) Parse(str string) error {
	s.funcDesc = nil

	arr := strings.Split(str, ",")

	for i := 0; i < len(arr); i++ {
		err := s.parseFunctionWithPrefix(arr[i])
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *tparserImpl) Get() []FunctionDescribe {
	return s.funcDesc
}

func (s *tparserImpl) parseFunction(funcStr string, desc *FunctionDescribe) error {

	var err error

	arr := strings.Split(funcStr, "@")

	if len(arr) > 3 {
		return fmt.Errorf("cant more than 3@ per function: %s", funcStr)
	}

	desc.FunctionName = arr[0]

	if desc.FunctionName == "" {
		return fmt.Errorf("no trace function name input")
	}

	if len(arr) <= 1 {
		return nil
	}

	desc.ParamIndex1, err = strconv.Atoi(arr[1])
	if err != nil || desc.ParamIndex1 <= 0 {
		return fmt.Errorf("param index1 must be >=1 ")
	}

	if len(arr) == 3 {
		if arr[2] == "" {
			desc.ParamIndex2 = desc.ParamIndex1 + 1
		} else {
			desc.ParamIndex2, err = strconv.Atoi(arr[2])
		}
		if err != nil || desc.ParamIndex2 <= 0 {
			return fmt.Errorf("param index2 must be >=1 ")
		}
	}

	return nil
}

func (s *tparserImpl) parseFunctionWithPrefix(traceFunction string) error {

	arr := strings.SplitN(traceFunction, ":", 2)

	desc := FunctionDescribe{}

	var funcStr string

	if len(arr) == 2 {
		desc.Prefix = arr[0]
		funcStr = arr[1]
	} else {
		desc.Prefix = ""
		funcStr = arr[0]
	}

	err := s.parseFunction(funcStr, &desc)
	if err != nil {
		return err
	}

	s.funcDesc = append(s.funcDesc, desc)

	return nil
}
