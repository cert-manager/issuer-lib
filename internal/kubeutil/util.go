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

package kubeutil

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// setGroupVersionKind populates the Group and Kind fields of obj using the
// scheme type registry.
// Inspired by https://github.com/kubernetes-sigs/controller-runtime/issues/1735#issuecomment-984763173
func SetGroupVersionKind(scheme *runtime.Scheme, obj client.Object) error {
	gvks, unversioned, err := scheme.ObjectKinds(obj)
	if err != nil {
		return err
	}
	if unversioned {
		return fmt.Errorf("ObjectKinds unexpectedly returned unversioned: %#v", unversioned)
	}
	if len(gvks) != 1 {
		return fmt.Errorf("ObjectKinds unexpectedly returned zero or multiple gvks: %#v", gvks)
	}
	obj.GetObjectKind().SetGroupVersionKind(gvks[0])
	return nil
}

func NewListObject(scheme *runtime.Scheme, gvk schema.GroupVersionKind) (client.ObjectList, error) {
	list, err := scheme.New(gvk.GroupVersion().WithKind(gvk.Kind + "List"))
	if err != nil {
		return nil, err
	}

	listObj, ok := list.(client.ObjectList)
	if !ok {
		return nil, fmt.Errorf("list object of %v does not implement client.ObjectList", gvk)
	}

	return listObj, nil
}
