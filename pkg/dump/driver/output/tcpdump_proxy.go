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
	"os/exec"
)

type tcpdumpProxy interface {
	GetInput() *os.File
}

type tcpdumpProxyImpl struct {
	cmd       *exec.Cmd
	inputFile *os.File
}

func newTcpdumpProxy(out *os.File, flags string) tcpdumpProxy {
	s := &tcpdumpProxyImpl{}

	r1, w1, _ := os.Pipe()

	cmdStr := fmt.Sprintf("tcpdump -r - %v ", flags)

	s.cmd = exec.Command("bash", "-c", cmdStr)

	s.cmd.Stdin = r1
	s.cmd.Stdout = out

	s.inputFile = w1

	go s.run()

	return s
}

func (s *tcpdumpProxyImpl) GetInput() *os.File {
	return s.inputFile
}

func (s *tcpdumpProxyImpl) run() {
	err := s.cmd.Run()
	if err != nil {
		os.Exit(0)
	}
}
