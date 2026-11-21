// Command admissiond runs the admission webhook service.
//
// It can source policy from files (mounted ConfigMap) and/or SecurityPolicy
// custom resources, and it serves both /validate and /mutate plus /healthz,
// /readyz and /metrics.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/example/cluster-admission-guard/internal/admission"
	"github.com/example/cluster-admission-guard/internal/audit"
	"github.com/example/cluster-admission-guard/internal/metrics"
	"github.com/example/cluster-admission-guard/internal/store"
	"github.com/example/cluster-admission-guard/internal/webhook"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	if err := run(); err != nil {
		slog.Error("admissiond failed", "err", err)
		os.Exit(1)
	}
}

type config struct {
	listen           string
	tlsCert          string
	tlsKey           string
	policyDir        string
	useInCluster     bool
	kubeconfig       string
	auditPath        string
	plainHTTP        bool
	strictFailClosed bool
	watchInterval    time.Duration
	adminGroups      string
}

func run() error {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", ":8443", "address to listen on")
	flag.StringVar(&cfg.tlsCert, "tls-cert", "", "path to TLS certificate (required unless --plain-http)")
	flag.StringVar(&cfg.tlsKey, "tls-key", "", "path to TLS private key (required unless --plain-http)")
	flag.StringVar(&cfg.policyDir, "policy-dir", "/etc/admission-guard/policies", "directory of policy YAML files")
	flag.BoolVar(&cfg.useInCluster, "in-cluster", true, "read SecurityPolicy CRs and Namespaces from the cluster")
	flag.StringVar(&cfg.kubeconfig, "kubeconfig", "", "kubeconfig path for out-of-cluster use (implies --in-cluster=false when set)")
	flag.StringVar(&cfg.auditPath, "audit-log", "", "append JSON audit events to this file (empty: stdout is skipped)")
	flag.BoolVar(&cfg.plainHTTP, "plain-http", false, "serve plain HTTP (only for local testing behind a TLS-terminating proxy)")
	flag.BoolVar(&cfg.strictFailClosed, "strict-unlabelled-fail-closed", false, "treat namespaces with no enforcement label as strict when the policy store is unhealthy")
	flag.DurationVar(&cfg.watchInterval, "policy-reload-interval", 0, "poll the policy directory every interval (0 disables; inotify is not used to keep dependencies small)")
	flag.StringVar(&cfg.adminGroups, "admin-groups", "system:masters", "comma separated groups allowed to label a namespace enforcement=disabled")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if !cfg.plainHTTP && (cfg.tlsCert == "" || cfg.tlsKey == "") {
		return errors.New("--tls-cert and --tls-key are required unless --plain-http is set")
	}
	if cfg.kubeconfig != "" {
		cfg.useInCluster = true // means "use a cluster", source chosen below
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Policy sources.
	var sources []*store.SnapshotStore
	var fileStore *store.FileStore
	if cfg.policyDir != "" {
		fs, err := store.NewFileStore(cfg.policyDir)
		if err != nil {
			// A broken policy directory must not stop the process: the webhook
			// has to stay up to serve its health endpoints and to fail closed
			// for strict namespaces. It is reported loudly instead.
			logger.Error("policy directory failed to load; keeping previous/empty policy", "dir", cfg.policyDir, "err", err)
		}
		fileStore = fs
		sources = append(sources, fs.SnapshotStore)
	}

	var clusterStore *store.ClusterStore
	// The flag defaults to true so the manifest works out of the box. When no
	// cluster configuration is detectable the daemon degrades to file-only
	// policy instead of failing to start.
	clusterEnabled := cfg.useInCluster
	if clusterEnabled {
		restCfg, err := buildRESTConfig(cfg.kubeconfig)
		if err != nil {
			logger.Warn("no cluster configuration found; running with file policy only", "err", err)
			clusterEnabled = false
		} else {
			kube, err := kubernetes.NewForConfig(restCfg)
			if err != nil {
				return fmt.Errorf("build kubernetes client: %w", err)
			}
			dyn, err := dynamic.NewForConfig(restCfg)
			if err != nil {
				return fmt.Errorf("build dynamic client: %w", err)
			}
			clusterStore = store.NewClusterStore(kube, dyn)
			if err := clusterStore.Run(ctx); err != nil {
				return fmt.Errorf("start cluster policy store: %w", err)
			}
			sources = append(sources, clusterStore.SnapshotStore)
		}
	}
	if len(sources) == 0 {
		return errors.New("no policy source configured: set --policy-dir or run in a cluster")
	}

	var storeImpl admission.Store
	if len(sources) == 1 {
		storeImpl = sources[0]
	} else {
		storeImpl = &store.Composed{Sources: sources}
	}

	// Remediation is handled by a dedicated engine so /mutate can rewrite and
	// /validate can never report a fix it did not apply.
	engine := admission.NewEngine(storeImpl)
	engine.Now = time.Now
	engine.AllowMutation = false
	engine.StrictWhenUnlabelled = cfg.strictFailClosed
	engine.AdminGroups = splitCSV(cfg.adminGroups)

	mutEngine := admission.NewEngine(storeImpl)
	mutEngine.Now = time.Now
	mutEngine.AllowMutation = true
	mutEngine.StrictWhenUnlabelled = cfg.strictFailClosed
	mutEngine.AdminGroups = engine.AdminGroups

	reg := metrics.New()
	var sinks []audit.Sink
	if cfg.auditPath != "" {
		sink, err := audit.NewFileSink(cfg.auditPath)
		if err != nil {
			return err
		}
		sinks = append(sinks, sink)
	}
	logger2 := &audit.Logger{Sinks: sinks}
	auditErr := reg.Counter("admission_guard_audit_write_errors_total", "Audit sink write failures.")
	logger2.OnError = func(err error) {
		auditErr.Inc()
		slog.Error("audit write failed", "err", err)
	}

	srv := webhook.NewServer(engine, logger2, reg)
	srv.MutateEngine = mutEngine

	httpSrv := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       90 * time.Second,
	}

	if cfg.watchInterval > 0 && fileStore != nil {
		go func() {
			t := time.NewTicker(cfg.watchInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					if err := fileStore.Reload(); err != nil {
						slog.Error("policy reload failed; previous policy remains active", "err", err)
					} else {
						slog.Info("policy reloaded", "policies", len(fileStore.Policies()))
					}
				}
			}
		}()
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	logger.Info("starting admission guard",
		"listen", cfg.listen,
		"tls", !cfg.plainHTTP,
		"policyDir", cfg.policyDir,
		"sources", len(sources),
		"policies", len(storeImpl.Policies()),
		"cluster", clusterEnabled,
	)

	if cfg.plainHTTP {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if err := httpSrv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func inClusterDetected() bool { return os.Getenv("KUBERNETES_SERVICE_HOST") != "" }

func buildRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	if inClusterDetected() {
		return rest.InClusterConfig()
	}
	// Fall back to the standard kubeconfig locations so `go run ./cmd/admissiond`
	// works on a developer machine with kubectl configured.
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{}).ClientConfig()
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}
