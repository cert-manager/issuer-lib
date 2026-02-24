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

package controllers

import (
	"context"
	"testing"

	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

func newTestManager(t *testing.T) manager.Manager {
	t.Helper()

	restCfg := &rest.Config{Host: "https://example"}

	mgr, err := manager.New(restCfg, manager.Options{
		Controller: config.Controller{
			// need to skip unique controller name validation
			// since all tests need a dedicated controller
			SkipNameValidation: ptr.To(true),
		},
	})
	if err != nil {
		t.Fatalf("failed to create test manager: %v", err)
	}

	return mgr
}

func TestCombinedControllerControllerOptions(t *testing.T) {
	t.Run("MaxConcurrentReconciles should default to 1", func(t *testing.T) {
		mgr := newTestManager(t)

		c := &CombinedController{
			ControllerOptions: controller.Options{
				MaxConcurrentReconciles: 0, // will be coerced to 1
			},
		}

		err := c.SetupWithManager(context.Background(), mgr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// assert coercion
		if c.ControllerOptions.MaxConcurrentReconciles != 1 {
			t.Errorf("expected MaxConcurrentReconciles to be coerced to 1, got %d", c.ControllerOptions.MaxConcurrentReconciles)
		}
	})

	t.Run("MaxConcurrentReconciles should be more than 1", func(t *testing.T) {
		mgr := newTestManager(t)

		c := &CombinedController{
			ControllerOptions: controller.Options{
				MaxConcurrentReconciles: 5,
			},
		}

		err := c.SetupWithManager(context.Background(), mgr)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if c.ControllerOptions.MaxConcurrentReconciles != 5 {
			t.Errorf("expected MaxConcurrentReconciles propagated value to be 5, got %d", c.ControllerOptions.MaxConcurrentReconciles)
		}
	})
}
