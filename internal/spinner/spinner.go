package spinner

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

// 3-line frames. ⊙ is always on the mid row at visual column 2.
// Each frame: [top row 5 chars] [before ⊙ 2 chars] [after ⊙ 2-3 chars] [bottom row 5 chars]
// · rotates around ⊙ clockwise: N → NE → E → SE → S → SW → W → NW
var frames = []struct {
	top    string
	before string // chars printed before ⊙ on mid row (always 2 visual chars)
	after  string // chars printed after ⊙ on mid row
	bottom string
}{
	{"  ·  ", "  ", "   ", "     "}, // N
	{"    ·", "  ", "   ", "     "}, // NE
	{"     ", "  ", "─· ", "     "}, // E
	{"     ", "  ", "   ", "    ·"}, // SE
	{"     ", "  ", "   ", "  ·  "}, // S
	{"     ", "  ", "   ", "·    "}, // SW
	{"     ", "·─", "   ", "     "}, // W
	{"·    ", "  ", "   ", "     "}, // NW
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

// Start launches the spinner animation in a background goroutine.
// It hides the cursor and draws a 3-line spinning graph icon.
func (s *Spinner) Start() {
	fmt.Print("\033[?25l") // hide cursor
	go func() {
		defer func() {
			fmt.Print("\033[?25h") // show cursor
			close(s.doneC)
		}()

		first := true
		i := 0
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopC:
				if !first {
					// move up 3 lines and erase them
					fmt.Print("\033[3A\r\033[K\n\033[K\n\033[K\033[3A\r")
				}
				return
			case <-ticker.C:
				f := frames[i%len(frames)]
				if !first {
					fmt.Print("\033[3A\r") // up 3 lines, go to col 0
				}
				// Row 0: outer node at top/bottom/side positions
				dim.Printf("   %s\n", f.top)
				// Row 1: ⊙ (colored) + orbital node chars + message
				dim.Printf("   %s", f.before)
				purple.Printf("⊙")
				dim.Printf("%s", f.after)
				cyan.Printf("  %s\n", s.msg)
				// Row 2
				dim.Printf("   %s\n", f.bottom)

				first = false
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
