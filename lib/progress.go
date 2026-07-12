package lib

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
)

// ProgressReporter emits machine-readable progress on stdout as lines of the
// form "PROGRESS <pct>\n", where pct is an integer 0..100. This is the protocol
// the tvault GUI (Tauri/Rust cli_runner) consumes: it reads stdout line by
// line, turns every "PROGRESS " line into a progress event, and skips those
// lines when accumulating the JSON token/log result — so progress output never
// collides with the JSON the same stdout carries.
//
// A line is emitted only when the integer percent advances, keeping the stream
// terse. An operation drives the reporter through one or more Phases, each
// mapped onto a sub-range of the overall 0..100 bar, so a multi-step operation
// (e.g. decrypt then extract) advances monotonically instead of resetting the
// GUI bar to 0 at each step.
type ProgressReporter struct {
	out io.Writer

	mu       sync.Mutex
	lastPct  int
	finished bool
}

// NewProgressReporter returns a reporter writing to stdout. lastPct starts at
// -1 so the first real update (including 0%) is always emitted.
func NewProgressReporter() *ProgressReporter {
	return &ProgressReporter{out: os.Stdout, lastPct: -1}
}

// Phase returns a handle that maps [0, total] processed bytes onto the integer
// percent sub-range [startPct, endPct] of the overall bar. A total <= 0 means
// the phase size is unknown, in which case any progress jumps straight to
// endPct. Nil-safe: a nil reporter yields a nil phase whose methods are no-ops.
func (p *ProgressReporter) Phase(startPct, endPct int, total int64) *ProgressPhase {
	if p == nil {
		return nil
	}

	return &ProgressPhase{rep: p, start: startPct, end: endPct, total: total}
}

// Finish emits a final "PROGRESS 100". Call it only on the success path — on
// failure the bar should stop wherever it was, not report completion.
func (p *ProgressReporter) Finish() {
	if p == nil {
		return
	}

	p.report(100)

	p.mu.Lock()
	p.finished = true
	p.mu.Unlock()
}

// report emits pct if it strictly advances the last reported value.
func (p *ProgressReporter) report(pct int) {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.finished || pct <= p.lastPct {
		return
	}

	p.lastPct = pct
	_, _ = fmt.Fprintf(p.out, "PROGRESS %d\n", pct)
}

// ProgressPhase reports byte progress for one step of an operation into its
// assigned percent sub-range of the parent reporter.
type ProgressPhase struct {
	rep     *ProgressReporter
	start   int
	end     int
	total   int64
	current int64 // atomic
}

// Add advances the phase by n bytes and reports the mapped percent. Nil-safe.
func (ph *ProgressPhase) Add(n int64) {
	if ph == nil || n <= 0 {
		return
	}

	ph.rep.report(ph.pct(atomic.AddInt64(&ph.current, n)))
}

func (ph *ProgressPhase) pct(cur int64) int {
	if ph.total <= 0 {
		return ph.end
	}

	if cur > ph.total {
		cur = ph.total
	}

	span := int64(ph.end - ph.start)

	return ph.start + int(cur*span/ph.total)
}

// WrapReader returns r wrapped so every byte read advances the phase.
func (ph *ProgressPhase) WrapReader(r io.Reader) io.Reader {
	if ph == nil {
		return r
	}

	return &phaseReader{r: r, ph: ph}
}

// WrapWriter returns w wrapped so every byte written advances the phase.
func (ph *ProgressPhase) WrapWriter(w io.Writer) io.Writer {
	if ph == nil {
		return w
	}

	return &phaseWriter{w: w, ph: ph}
}

type phaseReader struct {
	r  io.Reader
	ph *ProgressPhase
}

func (p *phaseReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.ph.Add(int64(n))

	return n, err
}

type phaseWriter struct {
	w  io.Writer
	ph *ProgressPhase
}

func (p *phaseWriter) Write(b []byte) (int, error) {
	n, err := p.w.Write(b)
	p.ph.Add(int64(n))

	return n, err
}
