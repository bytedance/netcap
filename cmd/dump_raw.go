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
package cmd

import (
	"log"

	"github.com/bytedance/netcap/pkg/dump"
	"github.com/spf13/cobra"
)

func rawCmdExampleString() string {
	str := "## raw mode is for the function such as : func(char *pkt_data, uint16_t pkt_size) in usr-mode app\n\n"
	str += "# capture raw function with tcpdump filter expression:\n"
	str += "netcap raw -f you_func\033[1;31m@1@2\033[0m -e \"tcp and port 80\" -t \"-nnve\" --pid 1111\n\n"
	str += "# Other are similar to mbuf-mode\n"
	return str
}

// rootCmd represents the base command when called without any subcommands
var rawCmd = &cobra.Command{
	Use:     "raw",
	Short:   "Dump raw(packet) with tcpdump expression",
	Example: rawCmdExampleString(),
	Run: func(cmd *cobra.Command, args []string) {
		doRawDump()
	},
}

func init() {
	rootCmd.AddCommand(rawCmd)

	dumpCmdLine(rawCmd)

	rawCmd.PersistentFlags().IntVarP(&mUserPID, "pid", "p", mUserPID, "PID of the target process")
}

func rawCheck() error {
	return commCheck()
}

func doRawDump() {

	err := rawCheck()
	if err != nil {
		log.Fatalf("raw mode param err: %v", err)
		return
	}

	opt := &dump.RawOption{
		Option: *commOption(),
		Pid:    mUserPID,
	}

	mbufDump, err := dump.NewRawDump(opt)
	if err != nil {
		log.Fatalf("Dump err: %v", err)
		return
	}

	runDump(mbufDump)
}
