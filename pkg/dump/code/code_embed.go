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
	_ "embed"
)

//

//go:embed c/skb.h
var codeSkbH string

//go:embed c/skb_comm.c
var codeSkbCommC string

//go:embed c/skb.c
var codeSkbC string

//go:embed c/skb_fake.c
var codeSkbFakeC string

//go:embed c/skb_kprobe.c
var codeSkbKprobeC string

//go:embed c/skb_tracepoint.c
var codeSkbTracepointC string

//go:embed c/comm.h
var codeCommH string

//go:embed c/user.h
var codeUserH string

//go:embed c/user_comm.h
var codeUserCommH string

//go:embed c/mbuf.c
var codeMbufC string

//go:embed c/mbuf_uprobe.c
var codeMbufUProbeC string

//go:embed c/mbuf_uprobe_vector.c
var codeMbufUProbeVectorC string

//go:embed c/mbuf_usdt.c
var codeMbufUSDTC string

//go:embed c/mbuf_usdt_vector.c
var codeMbufUSDTVectorC string

//go:embed c/raw_usdt.c
var codeRawUSDTC string

//go:embed c/raw_uprobe.c
var codeRawUprobeC string
