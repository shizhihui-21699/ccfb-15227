// Package metrics is a small Prometheus text-format registry. A full client
// library is avoided on purpose: this service sits on the critical path of
// every deployment, so its dependency surface stays small and auditable.
package metrics

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Registry holds counters and gauges.
type Registry struct {
	mu       sync.RWMutex
	counters map[string]*counterVec
	gauges   map[string]*gaugeVec
	start    time.Time
}

type counterVec struct {
	help   string
	labels []string
	mu     sync.Mutex
	values map[string]*atomic.Int64
	order  []string
}

type gaugeVec struct {
	help   string
	labels []string
	mu     sync.Mutex
	values map[string]*atomic.Int64
	order  []string
}

// New builds an empty registry.
func New() *Registry {
	return &Registry{
		counters: map[string]*counterVec{},
		gauges:   map[string]*gaugeVec{},
		start:    time.Now(),
	}
}

// Counter returns (creating if needed) a counter.
func (r *Registry) Counter(name, help string, labels ...string) *counterVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	c := &counterVec{help: help, labels: labels, values: map[string]*atomic.Int64{}}
	r.counters[name] = c
	return c
}

// Gauge returns (creating if needed) a gauge.
func (r *Registry) Gauge(name, help string, labels ...string) *gaugeVec {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g, ok := r.gauges[name]; ok {
		return g
	}
	g := &gaugeVec{help: help, labels: labels, values: map[string]*atomic.Int64{}}
	r.gauges[name] = g
	return g
}

func (c *counterVec) Inc(values ...string) {
	c.get(values...).Add(1)
}

func (g *gaugeVec) Set(v int64, values ...string) {
	g.get(values...).Store(v)
}

func (c *counterVec) get(values ...string) *atomic.Int64 {
	key := labelKey(c.labels, values)
	c.mu.Lock()
	ctr, ok := c.values[key]
	if !ok {
		ctr = &atomic.Int64{}
		c.values[key] = ctr
		c.order = append(c.order, key)
	}
	c.mu.Unlock()
	return ctr
}

func (g *gaugeVec) get(values ...string) *atomic.Int64 {
	key := labelKey(g.labels, values)
	g.mu.Lock()
	v, ok := g.values[key]
	if !ok {
		v = &atomic.Int64{}
		g.values[key] = v
		g.order = append(g.order, key)
	}
	g.mu.Unlock()
	return v
}

func labelKey(names, values []string) string {
	if len(values) != len(names) {
		panic(fmt.Sprintf("metric expects %d label values, got %d", len(names), len(values)))
	}
	var b strings.Builder
	for i, v := range values {
		if i > 0 {
			b.WriteByte(0)
		}
		b.WriteString(v)
	}
	return b.String()
}

// Handler serves the Prometheus text exposition format.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writeText(w, r)
	})
}

func writeText(w io.Writer, r *Registry) {
	fmt.Fprintf(w, "# HELP admission_guard_uptime_seconds Seconds since process start.\n")
	fmt.Fprintf(w, "# TYPE admission_guard_uptime_seconds gauge\n")
	fmt.Fprintf(w, "admission_guard_uptime_seconds %g\n", time.Since(r.start).Seconds())

	r.mu.RLock()
	defer r.mu.RUnlock()

	cnames := make([]string, 0, len(r.counters))
	for n := range r.counters {
		cnames = append(cnames, n)
	}
	sort.Strings(cnames)
	for _, name := range cnames {
		c := r.counters[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, c.help, name)
		c.mu.Lock()
		for _, key := range c.order {
			fmt.Fprintf(w, "%s%s %d\n", name, renderLabels(c.labels, key), c.values[key].Load())
		}
		c.mu.Unlock()
	}

	gnames := make([]string, 0, len(r.gauges))
	for n := range r.gauges {
		gnames = append(gnames, n)
	}
	sort.Strings(gnames)
	for _, name := range gnames {
		g := r.gauges[name]
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, g.help, name)
		g.mu.Lock()
		for _, key := range g.order {
			fmt.Fprintf(w, "%s%s %d\n", name, renderLabels(g.labels, key), g.values[key].Load())
		}
		g.mu.Unlock()
	}
}

func renderLabels(names []string, key string) string {
	if len(names) == 0 {
		return ""
	}
	parts := strings.Split(key, "\x00")
	var b strings.Builder
	b.WriteByte('{')
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		v := ""
		if i < len(parts) {
			v = parts[i]
		}
		b.WriteString(n)
		b.WriteByte('=')
		b.WriteString(strconv.Quote(v))
	}
	b.WriteByte('}')
	return b.String()
}
