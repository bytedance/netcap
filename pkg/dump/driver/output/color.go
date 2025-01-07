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

func getOutputColor(color string) (prefix string, suffix string) {
	if color == "" {
		color = "green"
	}

	if color == "red" {
		prefix = "\033[0;31m"
		suffix = "\033[0m"
	} else if color == "green" {
		prefix = "\033[0;32m"
		suffix = "\033[0m"
	} else if color == "yellow" {
		prefix = "\033[0;33m"
		suffix = "\033[0m"
	} else if color == "blue" {
		prefix = "\033[0;34m"
		suffix = "\033[0m"
	} else if color == "purple" {
		prefix = "\033[0;35m"
		suffix = "\033[0m"
	} else if color == "cyan" {
		prefix = "\033[0;36m"
		suffix = "\033[0m"
	} else {
		prefix = ""
		suffix = ""
	}
	return
}
