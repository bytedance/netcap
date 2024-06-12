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
package output

import (
	"fmt"
	"os"
)

type outputFile struct {
	pcapBase
}

func newOutputFile(opt *Option) (Operator, error) {

	path := opt.WritePcapFilePath

	s := &outputFile{}

	_ = os.Remove(path)

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}

	err = s.pcapBuild(opt, file)
	if err != nil {
		return nil, err
	}

	return s, nil
}

func (s *outputFile) OnTick(n uint32) (uint32, error) {
	return n, nil
}

func (s *outputFile) Output(raw []byte, n uint32) (uint32, error) {

	info, err := s.converter.Convert(raw)
	if err != nil {
		return n + 1, err
	}

	s.pcapOutput(info, n)

	if s.extendOper == nil {
		fmt.Printf("\rcapture packet: %5d", n+1)
	}

	return n + 1, nil
}

func (s *outputFile) Close() {

	s.pcapClose()

	fmt.Printf("\n")
}
