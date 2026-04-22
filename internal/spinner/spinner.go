package spinner

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

// 3-line frames showing all 8 outer nodes (·) at all times.
// One node per frame is highlighted (● or spoke char) to show rotation.
//
// Layout (with 3 leading spaces from Printf):
//   col 3: NW    col 5: N     col 7: NE
//   col 3: W     col 5: ⊙    col 7: E
//   col 3: SW    col 5: S     col 7: SE
//
// top[0,2,4] = NW,N,NE   before[0] = W   after[1] = E   bottom[0,2,4] = SW,S,SE
var frames = []struct {
	top    string // 5 chars: NW · N · NE
	before string // 2 chars: W then space (or W─ for W spoke)
	after  string // 3 chars: space E space (or ─● space for E spoke)
	bottom string // 5 chars: SW · S · SE
}{
	{"· | ·", "· ", " · ", "· · ·"}, // N  (spoke |)
	{"· · ●", "· ", " · ", "· · ·"}, // NE (highlight)
	{"· · ·", "· ", "─● ", "· · ·"}, // E  (spoke ─)
	{"· · ·", "· ", " · ", "· · ●"}, // SE (highlight)
	{"· · ·", "· ", " · ", "· | ·"}, // S  (spoke |)
	{"· · ·", "· ", " · ", "● · ·"}, // SW (highlight)
	{"· · ·", "●─", " · ", "· · ·"}, // W  (spoke ─)
	{"● · ·", "· ", " · ", "· · ·"}, // NW (highlight)
}

var (
	purple = color.New(color.FgMagenta, color.Bold)
	dim    = color.New(color.FgWhite, color.Faint)
	cyan   = color.New(color.FgCyan)
)

// Spinner shows an animated graph icon while a long operation runs.
type Spinner struct {
	msg   string
	stopC chan struct{}
	doneC chan struct{}
}

// New creates a spinner with a status message shown on the center row.
func New(msg string) *Spinner {
	return &Spinner{
		msg:   msg,
		stopC: make(chan struct{}),
		doneC: make(chan struct{}),
	}
}

func (s *Spinner) drawFrame(i int, first bool) {
	f := frames[i%len(frames)]
	if !first {
		fmt.Print("\033[3A\r")
	}
	dim.Printf("   %s\n", f.top)
	dim.Printf("   %s", f.before)
	purple.Printf("⊙")
	dim.Printf("%s", f.after)
	cyan.Printf("  %s\n", s.msg)
	dim.Printf("   %s\n", f.bottom)
}

// Start launches the spinner animation in a background goroutine.
// The first frame is drawn immediately inside the goroutine so it is
// always visible even if the operation completes in under 100ms.
func (s *Spinner) Start() {
	fmt.Print("\033[?25l") // hide cursor
	go func() {
		defer func() {
			fmt.Print("\033[?25h") // show cursor
			close(s.doneC)
		}()

		// Draw immediately — don't wait for first tick
		s.drawFrame(0, true)
		i := 1

		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopC:
				// erase the 3 spinner lines and reset cursor
				fmt.Print("\033[3A\r\033[K\n\033[K\n\033[K\033[3A\r")
				return
			case <-ticker.C:
				s.drawFrame(i, false)
				i++
			}
		}
	}()
}

// Stop halts the spinner and waits for the goroutine to finish.
func (s *Spinner) Stop() {
	close(s.stopC)
	<-s.doneC
}
