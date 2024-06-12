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
package gmt

import (
	"syscall"
	"time"
	"unsafe"
)

// Greenwich Mean Time

type Operator interface {
	// convert monotonic time to GMT
	MonotonicToGMT(ns uint64) uint64
}

type operatorImpl struct {
	deltaNS uint64
}

func NewGMT() Operator {
	s := &operatorImpl{}

	monic := monotonicNow()
	now := (uint64)(time.Now().UnixNano())
	s.deltaNS = now - monic

	return s
}

type timeSpec struct {
	Sec  uint64
	Nsec uint64
}

const (
	CLOCK_MONOTONIC = 1
)

func monotonicNow() uint64 {
	var ts timeSpec

	_, _, err := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, uintptr(CLOCK_MONOTONIC), uintptr(unsafe.Pointer(&ts)), 0)
	if err != 0 {
		return 0
	}
	return ts.Sec*1000000000 + ts.Nsec
}

func (s *operatorImpl) MonotonicToGMT(ns uint64) uint64 {

	return ns + s.deltaNS
}
