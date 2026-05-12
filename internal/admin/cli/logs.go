package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// TailOptions configures `netbrain-beacon logs tail`.
type TailOptions struct {
	// Path is the structured-log file to tail. Empty → derived from
	// state dir (state-dir/beacon.log).
	Path string
	// Follow keeps reading new lines as they arrive (like `tail -F`).
	// false means "print existing content then exit".
	Follow bool
	// MaxLines caps how many lines are printed before tailing (or
	// before exit if Follow is false). 0 means "all lines".
	MaxLines int
	// Grep filters lines case-insensitively. Empty → no filter.
	Grep string
	// Level filters by slog level prefix (e.g. "ERROR", "INFO"). Empty
	// → no filter.
	Level string
}

// Tail prints lines from a slog JSON log file matching the supplied
// filters. If Follow is true, blocks until the caller signals via the
// underlying io.Reader closing (typically a context cancel routed
// through an io.Pipe; for simplicity the CLI wrapper closes its file
// handle on signal).
//
// Tail does NOT parse JSON — it just filters on substring matches in
// the raw lines. This keeps the output forwardable to other tools
// (jq, less, grep) without re-encoding.
func Tail(out io.Writer, opts TailOptions) error {
	if opts.Path == "" {
		return errors.New("cli: log path required")
	}
	f, err := os.Open(opts.Path) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("cli: open log: %w", err)
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1<<20) // 1 MiB max line — log lines shouldn't ever hit this

	printed := 0
	for scanner.Scan() {
		line := scanner.Text()
		if opts.Level != "" && !strings.Contains(strings.ToUpper(line), opts.Level) {
			continue
		}
		if opts.Grep != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(opts.Grep)) {
			continue
		}
		_, _ = fmt.Fprintln(out, line)
		printed++
		if opts.MaxLines > 0 && printed >= opts.MaxLines {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("cli: scan: %w", err)
	}

	if !opts.Follow {
		return nil
	}

	// Follow mode: poll for new bytes every 200ms. Simpler than inotify
	// + portable across Linux/Windows. Bounded by ctx cancel from the
	// caller (which closes the file handle to abort the read).
	for {
		time.Sleep(200 * time.Millisecond)
		moreFound := false
		for scanner.Scan() {
			moreFound = true
			line := scanner.Text()
			if opts.Level != "" && !strings.Contains(strings.ToUpper(line), opts.Level) {
				continue
			}
			if opts.Grep != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(opts.Grep)) {
				continue
			}
			_, _ = fmt.Fprintln(out, line)
		}
		if !moreFound {
			if err := scanner.Err(); err != nil {
				if errors.Is(err, os.ErrClosed) {
					return nil
				}
				return fmt.Errorf("cli: scan: %w", err)
			}
		}
	}
}
