package cli

import (
	"bufio"
	"context"
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
	// PollInterval is the follow-mode poll cadence. Zero defaults to
	// 200ms. Exposed for tests that need a tighter loop.
	PollInterval time.Duration
}

// Tail prints lines from a slog JSON log file matching the supplied
// filters. If Follow is true, blocks until ctx is cancelled.
//
// Tail does NOT parse JSON — it just filters on substring matches in
// the raw lines. This keeps the output forwardable to other tools
// (jq, less, grep) without re-encoding.
//
// Implementation note: uses bufio.Reader (not bufio.Scanner) because
// Scanner latches an EOF "done" state — once Scan() returns false, the
// scanner is finished even if the underlying file grows. Reader has no
// such state and re-reads from the file on each ReadBytes call, which
// is what `tail -F` requires.
func Tail(ctx context.Context, out io.Writer, opts TailOptions) error {
	if opts.Path == "" {
		return errors.New("cli: log path required")
	}
	f, err := os.Open(opts.Path) //nolint:gosec // operator-supplied path
	if err != nil {
		return fmt.Errorf("cli: open log: %w", err)
	}
	defer func() { _ = f.Close() }()

	r := bufio.NewReaderSize(f, 64*1024)

	printed := 0
	emit := func(line string) bool {
		if opts.Level != "" && !strings.Contains(strings.ToUpper(line), opts.Level) {
			return false
		}
		if opts.Grep != "" && !strings.Contains(strings.ToLower(line), strings.ToLower(opts.Grep)) {
			return false
		}
		_, _ = fmt.Fprintln(out, strings.TrimRight(line, "\r\n"))
		printed++
		return opts.MaxLines > 0 && printed >= opts.MaxLines
	}

	// Initial drain — read every complete line that already exists on
	// disk. Stops at the first short read (EOF or partial trailing line)
	// so we hand-off cleanly to the follow-mode poll loop.
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 && strings.HasSuffix(line, "\n") {
			if emit(line) {
				return nil
			}
			continue
		}
		// Hit EOF (with or without a partial trailing line that has no
		// terminator yet). Stop the initial drain — any partial bytes
		// are buffered in r and ReadString will pick up where it left
		// off on the next call.
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("cli: read log: %w", err)
		}
	}

	if !opts.Follow {
		return nil
	}

	// Follow mode: poll with a Ticker, select against ctx.Done() so a
	// signal-cancel returns nil promptly. Each tick attempts to read
	// every line that has become available since the last tick.
	interval := opts.PollInterval
	if interval == 0 {
		interval = 200 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		for {
			line, err := r.ReadString('\n')
			if len(line) > 0 && strings.HasSuffix(line, "\n") {
				if emit(line) {
					return nil
				}
				continue
			}
			// Either EOF with no further line, or a partial line that
			// will complete on a later tick. Stop this tick's read
			// loop — the buffered partial stays inside r.
			if err == io.EOF || err == nil {
				break
			}
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			return fmt.Errorf("cli: read log: %w", err)
		}
	}
}
