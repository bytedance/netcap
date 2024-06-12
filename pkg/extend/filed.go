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
package extend

import (
	"fmt"

	"github.com/bytedance/netcap/pkg/util"
)

type filedOperator interface {
	Convert(data []byte) ([]byte, string)
}

type structField struct {
	fieldName    string
	fieldType    string
	outputFormat string
}

func (s *structField) getFormatString(d string) string {

	f := s.fieldName + ": "

	if s.outputFormat != "" {
		f += s.outputFormat
	} else {
		f += d
	}
	return f
}

func (s *structField) Convert(data []byte) ([]byte, string) {

	if s.fieldType == "int8" || s.fieldType == "int8_t" || s.fieldType == "char" {
		v := int8(data[0])

		output := fmt.Sprintf(s.getFormatString("%d"), v)
		return data[1:], output

	} else if s.fieldType == "uint8" || s.fieldType == "uint8_t" || s.fieldType == "uchar" {
		v := uint8(data[0])

		output := fmt.Sprintf(s.getFormatString("%d"), v)
		return data[1:], output

	} else if s.fieldType == "int16" || s.fieldType == "int16_t" {

		v := int16(util.NativeEndian.Uint16(data[:]))

		output := fmt.Sprintf(s.getFormatString("%d"), v)
		return data[2:], output

	} else if s.fieldType == "uint16" || s.fieldType == "uint16_t" {

		v := util.NativeEndian.Uint16(data[:])

		output := fmt.Sprintf(s.getFormatString("%d"), v)
		return data[2:], output

	} else if s.fieldType == "int" || s.fieldType == "int32_t" {
		tmp := util.NativeEndian.Uint32(data[:])
		v := int(tmp)

		form := s.getFormatString("%d")
		output := fmt.Sprintf(form, v)
		return data[4:], output

	} else if s.fieldType == "uint32" || s.fieldType == "uint32_t" {

		v := util.NativeEndian.Uint32(data[:])

		output := fmt.Sprintf(s.getFormatString("%d"), v)
		return data[4:], output

	} else if s.fieldType == "int64" || s.fieldType == "int64_t" {

		v := int64(util.NativeEndian.Uint64(data[:]))

		output := fmt.Sprintf(s.getFormatString("%d"), v)
		return data[8:], output
	} else if s.fieldType == "uint64" || s.fieldType == "uint64_t" {

		v := util.NativeEndian.Uint64(data[:])

		output := fmt.Sprintf(s.getFormatString("%d"), v)
		return data[8:], output
	}

	return data, ""
}

func newField(n string, t string, f string) filedOperator {

	s := &structField{
		fieldName:    n,
		fieldType:    t,
		outputFormat: f,
	}

	return s
}
