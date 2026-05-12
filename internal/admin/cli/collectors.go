package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"

	"github.com/velonet/netbrain-beacon/internal/collectors"
)

// CollectorsReport is the structured output of `netbrain-beacon collectors`.
type CollectorsReport struct {
	Collectors []CollectorEntry `json:"collectors"`
}

// CollectorEntry is one row.
type CollectorEntry struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
}

// CollectStateFromRegistry reads the registry's States and returns a
// sorted CollectorsReport. The daemon embeds the registry; the CLI
// status path snapshots it at call time.
//
// This function is used at runtime by the daemon's embedded CLI handler.
// For the no-running-daemon case, the CLI subcommand stub returns a
// "no daemon running" message instead.
func CollectStateFromRegistry(r *collectors.Registry) *CollectorsReport {
	states := r.States()
	out := make([]CollectorEntry, 0, len(states))
	for _, s := range states {
		out = append(out, CollectorEntry{Name: s.Name, Running: s.Running})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return &CollectorsReport{Collectors: out}
}

// FormatCollectorsHuman renders the report in human-readable form.
func FormatCollectorsHuman(w io.Writer, r *CollectorsReport) {
	if len(r.Collectors) == 0 {
		_, _ = fmt.Fprintln(w, "No collectors registered.")
		return
	}
	_, _ = fmt.Fprintln(w, "COLLECTOR  RUNNING")
	for _, c := range r.Collectors {
		status := "no"
		if c.Running {
			status = "yes"
		}
		_, _ = fmt.Fprintf(w, "%-10s %s\n", c.Name, status)
	}
}

// FormatCollectorsJSON writes the report as indented JSON.
func FormatCollectorsJSON(w io.Writer, r *CollectorsReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
