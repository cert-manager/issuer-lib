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

package cmtime

import (
	"time"

	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	clocktesting "k8s.io/utils/clock/testing"
)

var FakeTime = time.Now()

// We use an init function to set the fake clock, so that it is set only once
// and the tests don't interfere with each other.
func init() {
	cmutil.Clock = clocktesting.NewFakeClock(FakeTime)
}
