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
	"fmt"

	"github.com/spf13/cobra"
)

var (
	GitCommit  = ""
	GitBranch  = ""
	GitState   = ""
	GitSummary = ""
	BuildDate  = ""
	Version    = "1.0.1"
)

func dumpVersion() {
	fmt.Printf("GitCommit  : %s\n", GitCommit)
	fmt.Printf("GitBranch  : %s\n", GitBranch)
	fmt.Printf("GitSummary : %s\n", GitSummary)
	fmt.Printf("BuildDate  : %s\n", BuildDate)
	fmt.Printf("Version    : %s\n", Version)
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Version of netcap",
	Run: func(cmd *cobra.Command, args []string) {
		dumpVersion()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
