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

package testcontext

import (
	"context"
	"os"
	"os/signal"
	"testing"
	"time"
)

func ForTest(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	shuttingDown := make(chan struct{})
	finished := make(chan struct{})
	t.Cleanup(func() {
		close(shuttingDown)
		<-finished
	})

	c := make(chan os.Signal, 2)
	signal.Notify(c, shutdownSignals...)
	go func() {
		defer close(finished)

		select {
		case <-c:
			cancel()
		case <-shuttingDown:
			return
		}

		select {
		case <-c:
			os.Exit(1) // second signal. Exit directly.
		case <-shuttingDown:
			return
		}
	}()

	if deadline, ok := t.Deadline(); ok {
		var cancel context.CancelFunc
		// cancel context before panic ( give 5 seconds to shutdown )
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-5*time.Second))
		t.Cleanup(cancel)
	}

	return ctx
}
