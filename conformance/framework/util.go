/*
Copyright 2020 The cert-manager Authors.

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

package framework

import (
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"

	"k8s.io/component-base/featuregate"

	. "github.com/cert-manager/issuer-lib/conformance/framework/log"
)

func nowStamp() string {
	return time.Now().Format(time.StampMilli)
}

func Failf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Logf(msg)
	Fail(nowStamp()+": "+msg, 1)
}

func Skipf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	Logf("INFO", msg)
	Skip(nowStamp() + ": " + msg)
}

func RequireFeatureGate(f *Framework, featureSet featuregate.FeatureGate, gate featuregate.Feature) {
	if !featureSet.Enabled(gate) {
		Skipf("feature gate %q is not enabled, skipping test", gate)
	}
}
