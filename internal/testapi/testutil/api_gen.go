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

package testutil

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/internal/testapi/api"
)

type TestIssuerModifier func(*api.TestIssuer)

func TestIssuer(name string, mods ...TestIssuerModifier) *api.TestIssuer {
	c := &api.TestIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TestIssuer",
			APIVersion: api.SchemeGroupVersion.Identifier(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func TestIssuerFrom(cr *api.TestIssuer, mods ...TestIssuerModifier) *api.TestIssuer {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

func SetTestIssuerNamespace(namespace string) TestIssuerModifier {
	return func(si *api.TestIssuer) {
		si.Namespace = namespace
	}
}

func SetTestIssuerGeneration(generation int64) TestIssuerModifier {
	return func(si *api.TestIssuer) {
		si.Generation = generation
	}
}

func SetTestIssuerStatusCondition(
	clock clock.PassiveClock,
	conditionType string,
	status metav1.ConditionStatus,
	reason, message string,
) TestIssuerModifier {
	return func(si *api.TestIssuer) {
		conditions.SetIssuerStatusCondition(
			clock,
			si.Status.Conditions,
			&si.Status.Conditions,
			si.Generation,
			conditionType,
			status,
			reason,
			message,
		)
	}
}

type TestClusterIssuerModifier func(*api.TestClusterIssuer)

func TestClusterIssuer(name string, mods ...TestClusterIssuerModifier) *api.TestClusterIssuer {
	c := &api.TestClusterIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TestClusterIssuer",
			APIVersion: api.SchemeGroupVersion.Identifier(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func TestClusterIssuerFrom(cr *api.TestClusterIssuer, mods ...TestClusterIssuerModifier) *api.TestClusterIssuer {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

func SetTestClusterIssuerGeneration(generation int64) TestClusterIssuerModifier {
	return func(si *api.TestClusterIssuer) {
		si.Generation = generation
	}
}

func SetTestClusterIssuerStatusCondition(
	clock clock.PassiveClock,
	conditionType string,
	status metav1.ConditionStatus,
	reason, message string,
) TestClusterIssuerModifier {
	return func(si *api.TestClusterIssuer) {
		conditions.SetIssuerStatusCondition(
			clock,
			si.Status.Conditions,
			&si.Status.Conditions,
			si.Generation,
			conditionType,
			status,
			reason,
			message,
		)
	}
}
