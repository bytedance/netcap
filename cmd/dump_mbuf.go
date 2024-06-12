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

var (
	mUserPID int = 0
)

func mbufCmdExampleString() string {
	str := "## mbuf mode is for the DPDK app\n\n"
	str += "# capture dpdk function with tcpdump filter expression:\n"
	str += "netcap mbuf -f you_func@1 -e \"tcp and port 80\" -t \"-nnve\" --pid 1111\n\n"

	str += "# capture dpdk vector mbufs function, such as: vec_func(struct rte_mbuf **mbufs, uint16_t mbuf_size):\n"
	str += "netcap mbuf -f vec_func\033[1;32m@1@2\033[0m -e \"tcp and port 80\" -t \"-nnve\" --pid 1111\n\n"

	str += "# capture func_a and func_vector_b(vector fucntion):\n"
	str += "netcap mbuf -f func_a@1\033[1;32m,\033[0mfunc_vector_b\033[1;32m@1@2\033[0m -e \"tcp\" --pid 111\n\n"

	str += "# capture vector function vfunc, functon func_a, usdt ufunc:\n"
	str += "netcap mbuf -f vfunc@1@2,func_a@1,usdt:ufunc@1 --pid 111\n\n"

	str += "# --gather and --user-action are similar to skb-mode\n"

	return str
}

// rootCmd represents the base command when called without any subcommands
var mbufCmd = &cobra.Command{
	Use:     "mbuf",
	Short:   "Dump mbuf with tcpdump expression",
	Example: mbufCmdExampleString(),
	Run: func(cmd *cobra.Command, args []string) {
		doMbufDump()
	},
}

func init() {
	rootCmd.AddCommand(mbufCmd)

	dumpCmdLine(mbufCmd)

	mbufCmd.PersistentFlags().IntVarP(&mUserPID, "pid", "p", mUserPID, "PID of the target process")
}

func mbufCheck() error {
	return commCheck()
}

func doMbufDump() {

	err := mbufCheck()
	if err != nil {
		log.Fatalf("mbuf mode param err: %v", err)
		return
	}

	opt := &dump.MbufOption{
		Option: *commOption(),
		Pid:    mUserPID,
	}

	mbufDump, err := dump.NewMbufDump(opt)
	if err != nil {
		log.Fatalf("Dump err: %v", err)
		return
	}

	runDump(mbufDump)
}
