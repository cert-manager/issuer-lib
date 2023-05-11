/*
Copyright 2023 The cert-manager Authors.

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

package errormatch

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cert-manager/issuer-lib/internal/tests/ptr"
)

type Matcher func(t testing.TB, err error) bool

func newMatcherPtr(matcher Matcher) *Matcher {
	return ptr.New(matcher)
}

func NoError() *Matcher {
	return newMatcherPtr(func(tb testing.TB, err error) bool {
		tb.Helper()

		return assert.NoError(tb, err)
	})
}

func ErrorContains(contains string) *Matcher {
	return newMatcherPtr(func(tb testing.TB, err error) bool {
		tb.Helper()

		return assert.ErrorContains(tb, err, contains)
	})
}
