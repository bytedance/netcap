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
	"regexp"
	"strings"
)

type Option struct {
	UserActionCode string
}

type Operator interface {
	Convert(data []byte) string

	Close()
}

type operatorImpl struct {
	fields []filedOperator

	prefix string
	suffix string
}

func New(opt *Option) Operator {

	code := opt.UserActionCode

	if code == "" {
		return nil
	}

	e := &operatorImpl{
		prefix: "{",
		suffix: "}",
	}

	e.parse(code)

	return e
}

func (s *operatorImpl) Convert(data []byte) string {
	ret := s.prefix

	for _, field := range s.fields {
		var str string
		data, str = field.Convert(data)

		ret += str + "; "
	}
	ret += s.suffix

	return ret
}

func (s *operatorImpl) Close() {

}

func (s *operatorImpl) parse(str string) {
	mode := `(?s)struct\s+xcap_user_extend\s+{(.+?)}`

	reg := regexp.MustCompile(mode)

	match := reg.FindStringSubmatch(str)

	if len(match) <= 1 {
		return
	}

	arr := strings.Split(match[1], "\n")

	regType := regexp.MustCompile(`\s+(\S+)\s+(\S+)\s*`)
	regFormat := regexp.MustCompile(`\s*//\s*format:\s(\S+)`)

	for i := 0; i < len(arr); i++ {
		s.parseLine(arr[i], regType, regFormat)
	}
}

func (s *operatorImpl) parseLine(line string, regType *regexp.Regexp, regFormat *regexp.Regexp) {

	arr := strings.SplitN(line, ";", 2)

	if len(arr) != 2 {
		return
	}

	match := regType.FindStringSubmatch(arr[0])
	match2 := regFormat.FindStringSubmatch(arr[1])

	if len(match) != 3 {
		return
	}

	t := match[1]
	n := match[2]
	f := ""

	if len(match2) == 2 {
		f = match2[1]
	}

	s.fields = append(s.fields, newField(n, t, f))
}
