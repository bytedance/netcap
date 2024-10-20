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
package code

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func getSkbOffsetOnTracepoint(title string, name string) (int, error) {

	path := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/format", title, name)

	str, err := _readFile(path)
	if err != nil {
		return 0, err
	}

	arr := strings.Split(str, "\n")

    mode := `\s*field:(const\s+)*void\s+\*\s+skbaddr;\s+offset:(\d+);`

	reg := regexp.MustCompile(mode)

	for i := 0; i < len(arr); i++ {
		match := reg.FindStringSubmatch(arr[i])

		if len(match) <= 1 {
			continue
		}
        return strconv.Atoi(match[len(match)-1])
	}

	return 0, fmt.Errorf("tracepoint does not has skb param: %s", path)
}
