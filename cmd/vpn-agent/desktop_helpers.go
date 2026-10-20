package main

import (
	"log"
	"os/exec"
	"strings"
	"time"
)

var desktopHelpers = []string{"zenity", "wl-clipboard"}

const (
	helpersRetry    = 5 * time.Minute
	helpersAttempts = 288
)

func keepDesktopHelpers(run func(args ...string) ([]byte, error), sleep func(time.Duration)) {
	for attempt := 0; attempt < helpersAttempts; attempt++ {
		if attempt > 0 {
			sleep(helpersRetry)
		}
		out, err := run(append([]string{"showauto"}, desktopHelpers...)...)
		if err != nil {
			continue
		}
		auto := strings.Fields(string(out))
		if len(auto) == 0 {
			return
		}
		if _, err := run(append([]string{"manual"}, auto...)...); err == nil {
			log.Printf("desktop helpers kept as manually installed: %s", strings.Join(auto, " "))
			return
		}
	}
	log.Printf("desktop helpers were not marked as manually installed")
}

func aptMarkRun(args ...string) ([]byte, error) {
	bin, err := findBinary(aptMarkCandidates)
	if err != nil {
		return nil, err
	}
	return exec.Command(bin, args...).Output() //nolint:gosec
}
