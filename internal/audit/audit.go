// Package audit records admission decisions.
//
// Every non-trivial decision is recorded: denials, remediations, exemptions and
// degraded/fail-open handling. A component that can be configured to fail open
// must leave a durable trace of every time it did.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Event is one audit record.
type Event struct {
	Time       time.Time       `json:"time"`
	UID        string          `json:"uid,omitempty"`
	Operation  string          `json:"operation"`
	Kind       string          `json:"kind"`
	Group      string          `json:"group,omitempty"`
	Version    string          `json:"version,omitempty"`
	Namespace  string          `json:"namespace,omitempty"`
	Name       string          `json:"name"`
	User       string          `json:"user,omitempty"`
	UserGroups []string        `json:"userGroups,omitempty"`
	Allowed    bool            `json:"allowed"`
	Degraded   bool            `json:"degraded,omitempty"`
	Reason     string          `json:"degradedReason,omitempty"`
	Policies   []string        `json:"policies,omitempty"`
	Reasons    []string        `json:"denialReasons,omitempty"`
	Warnings   []string        `json:"warnings,omitempty"`
	Findings   []FindingRecord `json:"findings,omitempty"`
	// Exemptions lists honoured exemption IDs with their expiry, so risk that
	// is about to return is visible in the audit stream.
	Exemptions []ExemptionRecord `json:"exemptions,omitempty"`
	Patch      json.RawMessage   `json:"patch,omitempty"`
	DurationMs int64             `json:"durationMs"`
}

// FindingRecord is the audit-friendly subset of a finding.
type FindingRecord struct {
	Policy      string `json:"policy"`
	Rule        string `json:"rule"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
	Disposition string `json:"disposition"`
	Path        string `json:"path,omitempty"`
	Container   string `json:"container,omitempty"`
	Message     string `json:"message"`
	Exemption   string `json:"exemption,omitempty"`
}

// ExemptionRecord appears when an exemption suppressed a finding.
type ExemptionRecord struct {
	ID        string    `json:"id"`
	Policy    string    `json:"policy"`
	Rule      string    `json:"rule"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// Sink receives events. Implementations must be safe for concurrent use.
type Sink interface {
	Write(Event) error
	Close() error
}

// JSONSink writes one JSON object per line.
type JSONSink struct {
	mu sync.Mutex
	w  io.Writer
	c  io.Closer
}

// NewJSONSink wraps w. If c is nil, Close is a no-op.
func NewJSONSink(w io.Writer, c io.Closer) *JSONSink {
	return &JSONSink{w: w, c: c}
}

// NewFileSink opens path for appending.
func NewFileSink(path string) (*JSONSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}
	return NewJSONSink(f, f), nil
}

// Write implements Sink.
func (s *JSONSink) Write(e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.w.Write(append(b, '\n'))
	return err
}

// Close implements Sink.
func (s *JSONSink) Close() error {
	if s.c != nil {
		return s.c.Close()
	}
	return nil
}

// Logger fans events out to sinks. A failing sink never blocks admission; its
// errors are counted.
type Logger struct {
	Sinks []Sink
	// OnError observes sink failures (wired to a metric by the daemon).
	OnError func(error)
}

// Record writes to every sink. Errors are reported but never returned: an audit
// outage must not take down the cluster.
func (l *Logger) Record(e Event) {
	for _, s := range l.Sinks {
		if err := s.Write(e); err != nil && l.OnError != nil {
			l.OnError(err)
		}
	}
}

// Close closes all sinks.
func (l *Logger) Close() error {
	var first error
	for _, s := range l.Sinks {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
