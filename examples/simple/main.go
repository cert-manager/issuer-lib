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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"simple-issuer/api"
	"simple-issuer/controller"

	// Import all Kubernetes client auth plugins (e.g. Azure, GCP, OIDC, etc.)
	// to ensure that exec-entrypoint and run can make use of them.
	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// This value is replaced during the build process.
var Version = "v0.0.0"

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

func main() {
	opts := ctrlzap.Options{}
	opts.BindFlags(flag.CommandLine)

	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string

	var maxRetryDuration time.Duration
	var clusterResourceNamespace string

	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "The address the metric endpoint binds to.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", true,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")

	flag.DurationVar(&maxRetryDuration, "max-retry-duration", 2*time.Minute, "The max amount of time after certificate request creation that we will retry when an error occurs.")
	flag.StringVar(&clusterResourceNamespace, "cluster-resource-namespace", "", "The namespace for secrets in which cluster-scoped resources are found.")

	flag.Parse()

	opts.StacktraceLevel = zapcore.DPanicLevel
	logr := ctrlzap.New(ctrlzap.UseFlagOptions(&opts)).WithName("SI")

	// A nice feature that comes with client-go is its HTTP tracing that you can
	// usually enable with -v=6, -v=7 and -v=8. But since our binary does not
	// make use of klog, we can't just pass "-v". To be able to set the klog
	// level, we map each zap level to a corresponding klog level:
	//
	//  | zap flag                | unit8 | klog equiv  |
	//  |-------------------------|-------|-------------|
	//  | --zap-log-level=8       |  -8   |    -v=8     |  ^   For tracing
	//  | --zap-log-level=7       |  -7   |    -v=7     |  |   HTTP requests
	//  | --zap-log-level=6       |  -6   |    -v=6     |  v   to the apiserver.
	//  | --zap-log-level=5       |  -5   |    -v=5     |
	//  | --zap-log-level=4       |  -4   |    -v=4     |
	//  | --zap-log-level=3       |  -3   |    -v=3     |
	//  | --zap-log-level=2       |  -2   |    -v=2     |
	//  | --zap-log-level=1       |  -1   |    -v=1     |
	//  | --zap-log-level=debug   |  -1   |    -v=1     |
	//  | --zap-log-level=info    |   0   |    -v=0     |
	//  | --zap-log-level=warn    |   1   |    -v=0     |
	//  | --zap-log-level=error   |   2   |    -v=0     |
	//  | --zap-log-level=panic   |   4   |    -v=0     |
	//  | --zap-log-level=fatal   |   5   |    -v=0     |
	atomlvl, ok := opts.Level.(zap.AtomicLevel)
	if ok {
		zaplvl := atomlvl.Level()
		kloglvl := 0
		if zaplvl < 0 {
			kloglvl = -int(zaplvl)
		}
		dummy := flag.FlagSet{}
		klog.InitFlags(&dummy)

		// No way those can fail, so let's just ignore the errors.
		_ = dummy.Set("v", strconv.Itoa(kloglvl))
		_ = dummy.Parse(nil)
	}

	klog.SetLogger(logr)
	ctrl.SetLogger(logr)

	if err := run(
		clusterResourceNamespace,
		metricsAddr,
		enableLeaderElection,
		probeAddr,
	); err != nil {
		logr.Error(err, "error running manager")
		os.Exit(1)
	}
}

func run(
	clusterResourceNamespace string,
	metricsAddr string,
	enableLeaderElection bool,
	probeAddr string,
) error {
	setupLog := ctrl.Log.WithName("setup")

	setupLog.Info("versionInfo", "Version", Version)

	err := getInClusterNamespace(&clusterResourceNamespace)
	if err != nil {
		if errors.Is(err, errNotInCluster) {
			setupLog.Error(err, "please supply --cluster-resource-namespace")
		} else {
			setupLog.Error(err, "unexpected error while getting in-cluster Namespace")
		}
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(api.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme

	options := ctrl.Options{
		Scheme: scheme,
		Metrics: server.Options{
			BindAddress: metricsAddr,
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port: 9443,
		}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "f8d4bf2e.testing.cert-manager.io",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		LeaderElectionReleaseOnCancel: true,
	}

	ctx, cancel := context.WithCancel(ctrl.SetupSignalHandler())
	defer cancel()

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), options)
	if err != nil {
		return fmt.Errorf("unable to start manager: %w", err)
	}

	if err = (&controller.Signer{}).SetupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("unable to create controller: %w", err)
	}
	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up health check: %w", err)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		return fmt.Errorf("unable to set up ready check: %w", err)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("problem running manager: %w", err)
	}

	return nil
}

var errNotInCluster = errors.New("not running in-cluster")

// Copied from controller-runtime/pkg/leaderelection
func getInClusterNamespace(clusterResourceNamespace *string) error {
	if *clusterResourceNamespace != "" {
		return nil
	}

	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	_, err := os.Stat(inClusterNamespacePath)
	if os.IsNotExist(err) {
		return errNotInCluster
	} else if err != nil {
		return fmt.Errorf("error checking namespace file: %w", err)
	}

	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return fmt.Errorf("error reading namespace file: %w", err)
	}
	*clusterResourceNamespace = string(namespace)

	return nil
}
