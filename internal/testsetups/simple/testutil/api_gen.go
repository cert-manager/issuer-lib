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
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/clock"

	"github.com/cert-manager/issuer-lib/conditions"
	"github.com/cert-manager/issuer-lib/internal/testsetups/simple/api"
)

type SimpleIssuerModifier func(*api.SimpleIssuer)

func SimpleIssuer(name string, mods ...SimpleIssuerModifier) *api.SimpleIssuer {
	c := &api.SimpleIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SimpleIssuer",
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

func SimpleIssuerFrom(cr *api.SimpleIssuer, mods ...SimpleIssuerModifier) *api.SimpleIssuer {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

func SetSimpleIssuerNamespace(namespace string) SimpleIssuerModifier {
	return func(si *api.SimpleIssuer) {
		si.Namespace = namespace
	}
}

func SetSimpleIssuerGeneration(generation int64) SimpleIssuerModifier {
	return func(si *api.SimpleIssuer) {
		si.Generation = generation
	}
}

func SetSimpleIssuerStatusCondition(
	clock clock.PassiveClock,
	conditionType cmapi.IssuerConditionType,
	status cmmeta.ConditionStatus,
	reason, message string,
) SimpleIssuerModifier {
	return func(si *api.SimpleIssuer) {
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

type SimpleClusterIssuerModifier func(*api.SimpleClusterIssuer)

func SimpleClusterIssuer(name string, mods ...SimpleClusterIssuerModifier) *api.SimpleClusterIssuer {
	c := &api.SimpleClusterIssuer{
		TypeMeta: metav1.TypeMeta{
			Kind:       "SimpleClusterIssuer",
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

func SimpleClusterIssuerFrom(cr *api.SimpleClusterIssuer, mods ...SimpleClusterIssuerModifier) *api.SimpleClusterIssuer {
	cr = cr.DeepCopy()
	for _, mod := range mods {
		mod(cr)
	}
	return cr
}

func SetSimpleClusterIssuerGeneration(generation int64) SimpleClusterIssuerModifier {
	return func(si *api.SimpleClusterIssuer) {
		si.Generation = generation
	}
}

func SetSimpleClusterIssuerStatusCondition(
	clock clock.PassiveClock,
	conditionType cmapi.IssuerConditionType,
	status cmmeta.ConditionStatus,
	reason, message string,
) SimpleClusterIssuerModifier {
	return func(si *api.SimpleClusterIssuer) {
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
