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

package testresource

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var (
	_, b, _, _  = runtime.Caller(0)
	projectRoot = filepath.Join(filepath.Dir(b), "../../..")
	envsDir     = filepath.Join(projectRoot, "_bin", "envs")
)

type contextKey string

func (c contextKey) String() string {
	return string(c)
}

var (
	contextKeyTestMode = contextKey("test-mode")
)

type TestMode string

const (
	UnknownTest  TestMode = "UNKNOWN"
	UnitTest     TestMode = "UNIT"
	EndToEndTest TestMode = "E2E"
)

// Tries to extract the test mode from the context, if not
// set in the context, check if a TEST_MODE environment variable
// value was passed by make to the go test.
func determineSetupTestMode(ctx context.Context) TestMode {
	if mode := CurrentTestMode(ctx); mode != UnknownTest {
		return mode
	} else {
		// If 'make' is run before 'go', an environment value 'TEST_MODE' is set
		// by 'make' to indicate for what mode ('UNIT' or 'E2E') test dependencies
		// were setup before starting the go test.
		testMode := TestMode(os.Getenv("TEST_MODE"))

		if testMode == UnitTest || testMode == EndToEndTest {
			return testMode
		}

		return UnknownTest
	}
}

// Extract from the context what the test mode is of the current test.
// If value is not set, 'UnknownTest' is returned.
func CurrentTestMode(ctx context.Context) TestMode {
	if mode, ok := ctx.Value(contextKeyTestMode).(TestMode); ok {
		return mode
	} else {
		return UnknownTest
	}
}

// Require a dependency value to be set and return the value.
// These values are all provided by make and passed to golang using
// files in the envsDir folder.
func RequireValue(tb testing.TB, key string) string {
	tb.Helper()

	if value, ok := os.LookupEnv(key); !ok {
		tb.Fatalf("environment variable \"%s\" not set", key)
		return ""
	} else {
		return value
	}
}

// When running the go tests directly, the 'make' environment variables are
// not available, so here we run 'make' from go to generate all dependencies
// through make and set the correct environment variables.
func EnsureTestDependencies(tb testing.TB, ctx context.Context, testMode TestMode) context.Context {
	tb.Helper()

	// Skip test if the type is not unknown and differs from the provided type
	setupTestMode := determineSetupTestMode(ctx)
	if setupTestMode != UnknownTest && setupTestMode != testMode {
		tb.Skipf("Only running tests of type %s", setupTestMode)
	}

	// Only run make if the setup test mode is UNKNOWN (which means it was invoked through go)
	if setupTestMode != testMode {
		makeBin, err := exec.LookPath("make")
		if err != nil {
			tb.Fatalf("could not find make")
		}

		command := ""
		if testMode == UnitTest {
			command = "test-unit-deps"
		} else if testMode == EndToEndTest {
			command = "test-e2e-deps"
		} else {
			tb.Fatalf("unknown test mode specified: %v", testMode)
		}

		cmd := exec.Command(makeBin, command)

		cmd.Dir = projectRoot
		cmd.Env = []string{
			"HOME=" + os.Getenv("HOME"),
			"GOMODCACHE=" + os.Getenv("GOMODCACHE"),
			"GOPATH=" + os.Getenv("GOPATH"),
			"PATH=" + os.Getenv("PATH"),
			"PWD=" + projectRoot,
			// prevent '/etc/bash.bashrc: line 7: PS1: unbound variable'
			// warning because of non-interactive mode
			"PS1=",
		}

		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			tb.Fatalf("failed running make: %v", err)
		}
	}

	// 'make' passes the environment variables to 'go' by
	// writing them to files, 'go' reads these files in the
	// 'envsDir' and sets the environment variables.
	// this allows us to pass complex values from the child
	// 'make' process to its parent 'go'
	files, err := os.ReadDir(envsDir)
	if err != nil {
		tb.Fatal(err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		data, err := os.ReadFile(filepath.Join(envsDir, file.Name()))
		if err != nil {
			tb.Fatal(err)
		}

		err = os.Setenv(file.Name(), strings.TrimSpace(string(data)))
		if err != nil {
			tb.Fatal(err)
		}
	}

	if CurrentTestMode(ctx) == testMode {
		return ctx
	} else {
		// Update context with test type provided in the function argument
		// this can be used by test logic to determine in what kind of test
		// the logic is being executed.
		return context.WithValue(ctx, contextKeyTestMode, testMode)
	}
}
