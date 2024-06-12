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
package util

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
)

var (
	cmdLogger = NewLogger("cmd")
)

func BashRaw(cmdStr string) error {
	cmd := bashCmd(cmdStr)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func Bash(cmdStr string) error {
	var (
		err error
	)

	_, _, err = BashOutput(cmdStr)

	return err
}

func BashOutput(cmdStr string) (string, string, error) {
	var (
		err            error
		stdout, stderr bytes.Buffer
	)

	cmd := bashCmd(cmdStr)
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err = cmd.Run()

	cmdLogger.Debugf("[stdout] %s", stdout.String())
	if e := stderr.String(); e != "" {
		f := cmdLogger.Debugf
		if err != nil {
			f = cmdLogger.Errorf
		}
		f("[stderr] %s", e)
	}

	return stdout.String(), stderr.String(), err
}

func runCmd(cmd *exec.Cmd) {
	_ = cmd.Run()
}

func BashPipeInput(cmdStr string, output io.Writer) (io.WriteCloser, error) {
	var (
		err   error
		input io.WriteCloser
	)

	cmd := bashCmd(cmdStr)
	defer func() {
		if err == nil {
			go runCmd(cmd)
		}
	}()
	if output != nil {
		cmd.Stdout = output
	}
	input, err = cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("stdin pipe err : %v", err)
	}
	return input, err
}

func BashPipe(cmdStr string) (io.WriteCloser, io.ReadCloser, error) {
	var (
		err    error
		input  io.WriteCloser
		output io.ReadCloser
	)

	cmd := bashCmd(cmdStr)
	defer func() {
		if err == nil {
			go runCmd(cmd)
		}
	}()
	input, err = cmd.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("stdin pipe err : %v", err)
	}
	output, err = cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, nil, fmt.Errorf("stdout pipe err : %v", err)
	}
	return input, output, err
}

func bashCmd(cmdStr string) *exec.Cmd {
	cmdLogger.Debugf("exec `%v`", cmdStr)
	return exec.Command("bash", "-c", cmdStr)
}
