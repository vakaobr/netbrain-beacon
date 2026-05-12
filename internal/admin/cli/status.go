package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/vakaobr/netbrain-beacon/internal/enroll"
	"github.com/vakaobr/netbrain-beacon/internal/store"
	"github.com/vakaobr/netbrain-beacon/internal/transport"
)

// StatusReport is the structured output of `netbrain-beacon status`.
// Tests + the JSON output mode use the struct directly; the human-
// readable formatter renders the same data.
type StatusReport struct {
	Enrolled       bool                  `json:"enrolled"`
	BeaconID       string                `json:"beacon_id,omitempty"`
	EnrolledAt     string                `json:"enrolled_at,omitempty"`
	ServerURL      string                `json:"server_url,omitempty"`
	DEKVersion     int                   `json:"dek_version,omitempty"`
	CertExpiresAt  string                `json:"cert_expires_at,omitempty"`
	CertLifeRemain float64               `json:"cert_lifecycle_remaining,omitempty"`
	StoreBuckets   map[string]BucketStat `json:"store_buckets,omitempty"`
	StoreEvictLast string                `json:"store_evict_last,omitempty"`
	StateDir       string                `json:"state_dir"`
	ServerCheck    *ServerCheckReport    `json:"server_check,omitempty"`
	Warnings       []string              `json:"warnings,omitempty"`
}

// BucketStat is the per-bucket snapshot of records + bytes.
type BucketStat struct {
	Records int   `json:"records"`
	Bytes   int64 `json:"bytes"`
}

// CollectStatus reads every on-disk artifact under stateDir and assembles
// the StatusReport. Returns a partial report + warnings if some files are
// missing (e.g., not-yet-enrolled state); only returns an outright error
// for unrecoverable I/O failures.
func CollectStatus(stateDir string) (*StatusReport, error) {
	r := &StatusReport{
		StateDir:     stateDir,
		StoreBuckets: map[string]BucketStat{},
	}

	// Enrollment metadata.
	metaPath := filepath.Join(stateDir, enroll.MetadataFilename)
	raw, err := os.ReadFile(metaPath) //nolint:gosec // operator-supplied path
	if err == nil {
		var m enroll.Metadata
		if jerr := json.Unmarshal(raw, &m); jerr == nil && m.BeaconID.String() != "00000000-0000-0000-0000-000000000000" {
			r.Enrolled = true
			r.BeaconID = m.BeaconID.String()
			r.EnrolledAt = m.EnrolledAt.UTC().Format(time.RFC3339)
			r.ServerURL = m.ServerURL
			r.DEKVersion = m.DEKVersion
		}
	} else if !os.IsNotExist(err) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("metadata: %v", err))
	}

	// Cert expiry.
	certPath := filepath.Join(stateDir, enroll.BeaconCertFilename)
	if certBytes, err := os.ReadFile(certPath); err == nil { //nolint:gosec
		cert, perr := transport.ParseCertPEM(certBytes)
		if perr == nil {
			r.CertExpiresAt = cert.NotAfter.UTC().Format(time.RFC3339)
			r.CertLifeRemain = transport.LifecycleRemaining(cert, time.Now())
		} else {
			r.Warnings = append(r.Warnings, fmt.Sprintf("cert parse: %v", perr))
		}
	} else if !os.IsNotExist(err) {
		r.Warnings = append(r.Warnings, fmt.Sprintf("cert read: %v", err))
	}

	// bbolt store snapshot. Open read-only by passing a fresh Store —
	// because Open with no records is cheap, we use it for the count.
	if _, err := os.Stat(filepath.Join(stateDir, store.DefaultFilename)); err == nil {
		s, err := store.Open(stateDir, store.Options{OpenTimeout: 1 * time.Second})
		if err != nil && !errors.Is(err, store.ErrCorrupt) {
			r.Warnings = append(r.Warnings, fmt.Sprintf("store open: %v", err))
		} else if s != nil {
			for _, b := range []store.Bucket{store.BucketFlows, store.BucketLogs, store.BucketSNMP, store.BucketConfigs} {
				count, _ := s.Count(b)
				bytes, _ := s.Bytes(b)
				r.StoreBuckets[string(b)] = BucketStat{Records: count, Bytes: bytes}
			}
			if t, _ := s.EvictLast(); !t.IsZero() {
				r.StoreEvictLast = t.UTC().Format(time.RFC3339)
			}
			_ = s.Close()
		}
		if errors.Is(err, store.ErrCorrupt) {
			r.Warnings = append(r.Warnings, "store was corrupt and renamed aside; running on fresh DB")
		}
	}

	return r, nil
}

// FormatStatusHuman renders the StatusReport in human-readable form.
// Use FormatStatusJSON for machine consumption.
func FormatStatusHuman(w io.Writer, r *StatusReport) {
	if !r.Enrolled {
		_, _ = fmt.Fprintln(w, "Enrolled:    no")
		_, _ = fmt.Fprintf(w, "State dir:   %s\n", r.StateDir)
		_, _ = fmt.Fprintln(w, "Run 'netbrain-beacon enroll' to provision.")
	} else {
		_, _ = fmt.Fprintln(w, "Enrolled:    yes")
		_, _ = fmt.Fprintf(w, "Beacon ID:   %s\n", r.BeaconID)
		_, _ = fmt.Fprintf(w, "Enrolled at: %s\n", r.EnrolledAt)
		_, _ = fmt.Fprintf(w, "Server URL:  %s\n", r.ServerURL)
		_, _ = fmt.Fprintf(w, "DEK version: %d\n", r.DEKVersion)
		_, _ = fmt.Fprintf(w, "State dir:   %s\n", r.StateDir)
	}
	if r.CertExpiresAt != "" {
		_, _ = fmt.Fprintf(w, "Cert expires at: %s (%.1f%% lifecycle remaining)\n",
			r.CertExpiresAt, r.CertLifeRemain*100)
	}
	if len(r.StoreBuckets) > 0 {
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Store buckets (records / bytes):")
		for _, name := range []string{"flows", "logs", "snmp", "configs"} {
			bs, ok := r.StoreBuckets[name]
			if !ok {
				continue
			}
			_, _ = fmt.Fprintf(w, "  %-8s %7d / %10d\n", name, bs.Records, bs.Bytes)
		}
		if r.StoreEvictLast != "" {
			_, _ = fmt.Fprintf(w, "Last eviction: %s\n", r.StoreEvictLast)
		}
	}
	if r.ServerCheck != nil {
		_, _ = fmt.Fprintln(w, "")
		_, _ = fmt.Fprintln(w, "Server check (live mTLS round-trip):")
		sc := r.ServerCheck
		if !sc.Reachable {
			_, _ = fmt.Fprintf(w, "  reachable:        no\n  error:            %s\n", sc.Error)
		} else {
			_, _ = fmt.Fprintf(w, "  reachable:        yes (HTTP %d)\n", sc.HTTPStatus)
			if sc.ExpiresAt != "" {
				_, _ = fmt.Fprintf(w, "  expires_at:       %s (%d days)\n", sc.ExpiresAt, sc.DaysUntilExpiry)
			}
			if sc.RecommendedAction != "" {
				_, _ = fmt.Fprintf(w, "  recommended:      %s\n", sc.RecommendedAction)
			}
			if sc.RevocationReason != "" {
				_, _ = fmt.Fprintf(w, "  revocation:       %s\n", sc.RevocationReason)
			}
		}
	}
	for _, w2 := range r.Warnings {
		_, _ = fmt.Fprintf(w, "WARN: %s\n", w2)
	}
}

// FormatStatusJSON writes the status as indented JSON.
func FormatStatusJSON(w io.Writer, r *StatusReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
