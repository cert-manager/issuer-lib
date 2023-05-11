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
	"context"
	"fmt"
	"sync"

	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type EventSource interface {
	AddConsumer(gvk schema.GroupVersionKind) source.Source
	ReportError(gvk schema.GroupVersionKind, namespacedName types.NamespacedName, err error) error
	HasReportedError(gvk schema.GroupVersionKind, namespacedName types.NamespacedName) error
}

type resource struct {
	gvk            schema.GroupVersionKind
	namespacedName types.NamespacedName
}

type eventSource struct {
	mu         sync.RWMutex
	dest       map[schema.GroupVersionKind]workqueue.RateLimitingInterface
	invalidate sync.Map
}

func NewEventStore() EventSource {
	return &eventSource{
		dest: make(map[schema.GroupVersionKind]workqueue.RateLimitingInterface),
	}
}

func (es *eventSource) HasReportedError(gvk schema.GroupVersionKind, namespacedName types.NamespacedName) error {
	err, ok := es.invalidate.LoadAndDelete(resource{
		gvk:            gvk,
		namespacedName: namespacedName,
	})
	if !ok {
		return nil
	}
	return err.(error)
}

func (es *eventSource) ReportError(gvk schema.GroupVersionKind, namespacedName types.NamespacedName, err error) error {
	es.mu.RLock()
	defer es.mu.RUnlock()

	if queue, ok := es.dest[gvk]; !ok {
		return fmt.Errorf("consumer for %v does not exist", gvk)
	} else {
		es.invalidate.Store(resource{
			gvk:            gvk,
			namespacedName: namespacedName,
		}, err)

		queue.Add(reconcile.Request{NamespacedName: namespacedName})
		return nil
	}
}

func (es *eventSource) AddConsumer(gvk schema.GroupVersionKind) source.Source {
	return &eventConsumer{
		register: func(queue workqueue.RateLimitingInterface) error {
			es.mu.Lock()
			defer es.mu.Unlock()

			_, ok := es.dest[gvk]
			if ok {
				return fmt.Errorf("consumer for %v already registered", gvk)
			}

			es.dest[gvk] = queue

			return nil
		},
	}
}

type eventConsumer struct {
	register func(queue workqueue.RateLimitingInterface) error
}

var _ source.Source = &eventConsumer{}

func (cs *eventConsumer) String() string {
	return fmt.Sprintf("EventConsumer: %p", cs)
}

// Start implements Source and should only be called by the Controller.
func (cs *eventConsumer) Start(_ context.Context, _ handler.EventHandler, queue workqueue.RateLimitingInterface, _ ...predicate.Predicate) error {
	if cs.register == nil {
		return fmt.Errorf("register function not provided")
	}

	err := cs.register(queue)
	cs.register = nil

	return err
}
