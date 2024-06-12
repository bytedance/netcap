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
	skbInterface     string = ""
	isDumpStack      bool   = false
	dumpStackColor   string = ""
	isSkbFakeHdr     bool   = false
	isUseSkbData     bool   = false
	useSkbDataOffset int32  = 0
)

func skbCmdExampleString() string {
	str := "## skb mode is for the kernel\n\n"
	str += "# simple used to caputre skb in icmp_rcv with tcpdump filter expression:\n"
	str += "netcap skb -f icmp_rcv@1 -e \"host 10.227.0.72\" \n\n"

	str += "# capture at tracepoint, and \033[1;31mDON'T\033[0m need @param at tracepoint\n"
	str += "netcap skb -f tracepoint:net:netif_receive_skb -i eth0 -e \"host 10.227.0.72\"\n\n"

	str += "# capture pcap with dump kstack:\n"
	str += "netcap skb -f tracepoint:skb:kfree_skb -e \"host 10.227.0.72\" \033[1;32m-S\033[0m \n\n"

	str += "# capture kernel function dev_queue_xmit at eth0 with tcpdump flags -nnve:\n"
	str += "netcap skb -f dev_queue_xmit@1 -e \"tcp and port 80\" -i eth0 \033[1;32m-t\033[0m \"-nnve\"\n\n"

	str += "# capture with user-filter or user-action:\n"
	str += "netcap skb -f icmp_rcv@1 -e \"host 10.227.0.72\" -i eth0 \033[1;32m--user-filter\033[0m filter.c\n"
	str += "netcap skb -f icmp_rcv@1 -e \"host 10.227.0.72\" -i eth0 \033[1;32m--user-action\033[0m action.c\n\n"

	str += "# capture in gather mode:\n"
	str += "netcap skb \033[1;32m-G\033[0m -f tracepoint:net:netif_receive_skb,ip_local_deliver@1,ip_local_deliver_finish@3,icmp_rcv@1 -e \"host 10.227.0.72 and icmp\" -i eth0\n\n"

	str += "# how to use --skb-data: \n"
	str += "Instead of use  : netcap skb -f icmp_rcv@1 -e \"host 10.227.0.72\" \n"
	str += "You can use     : netcap skb -f icmp_rcv@1 -e \"host 10.227.0.72\" --skb-data --skb-data-offset -34\n"
	str += "This -34 mean skb->data with an offset of -34 as packet begin. 34 = sizeof(iphdr)+sizeof(ethhdr).\n\n"

	str += "# captrue packet in TX which does't has some header, but can use --fake-hdr simulate these headers by socks:\n"
	str += "netcap skb -f __ip_finish_output@3 -e \"udp and host 10.227.0.72\" \033[1;32m--fake-hdr\033[0m\n"

	return str
}

// rootCmd represents the base command when called without any subcommands
var skbCmd = &cobra.Command{
	Use:     "skb",
	Short:   "Dump skb with tcpdump expression",
	Example: skbCmdExampleString(),
	Run: func(cmd *cobra.Command, args []string) {
		doSkbDump()
	},
}

func init() {
	rootCmd.AddCommand(skbCmd)

	dumpCmdLine(skbCmd)

	skbCmd.PersistentFlags().StringVarP(&skbInterface,
		"interface", "i", skbInterface, "net interface such as eth0")

	skbCmd.PersistentFlags().BoolVarP(&isDumpStack, "stack-dump", "S", isDumpStack,
		"dump stack with pcap, if has this flag then ignore --gather(-G) and -w")
	skbCmd.PersistentFlags().StringVarP(&dumpStackColor, "stack-dump-color", "", dumpStackColor,
		"stack dump output color: red|green|yellow|blue|purple|cyan")

	skbCmd.PersistentFlags().BoolVarP(&isSkbFakeHdr, "fake-hdr", "", isSkbFakeHdr,
		"fake skb's eth ip tcp or udp header by sock,\nIf has this flag then ignore --skb-data")

	skbCmd.PersistentFlags().BoolVarP(&isUseSkbData, "skb-data", "", isUseSkbData,
		"use skb->data and --skb-data-offset as offset to set packet begin, without this then auto set by netcap.")
	skbCmd.PersistentFlags().Int32VarP(&useSkbDataOffset, "skb-data-offset", "", useSkbDataOffset,
		"it's only work under --skb-data. Set the offset of skb->data for the begin data of packet.")

}

func skbCheck() error {
	return commCheck()
}

func doSkbDump() {

	err := skbCheck()
	if err != nil {
		log.Fatalf("skb mode param err: %v", err)
		return
	}

	opt := &dump.SkbOption{
		Option:         *commOption(),
		Interface:      skbInterface,
		IsDumpStack:    isDumpStack,
		DumpStackColor: dumpStackColor,
		IsFakeHdr:      isSkbFakeHdr,
		IsUseSkbData:   isUseSkbData,
		SkbDataOffset:  useSkbDataOffset,
	}

	skbDump, err := dump.NewSkbDump(opt)
	if err != nil {
		log.Fatalf("Dump err: %v", err)
		return
	}

	runDump(skbDump)

}
