package main

import (
	"log"
	"os"

	"github.com/vpn-vendor/vpn-panel-core/app/services/logsink"
	"github.com/vpn-vendor/vpn-panel-core/bootstrap"
	"github.com/vpn-vendor/vpn-panel-core/internal/cgroupstat"
	"github.com/vpn-vendor/vpn-panel-core/internal/logdedup"
)

func main() {

	out := logdedup.New(os.Stderr)
	log.SetFlags(0)
	log.SetOutput(out)
	logsink.SetOutput(out)

	if len(os.Args) == 1 {
		applyMemoryLimit()
	}

	app := bootstrap.Boot()

	if err := bootstrap.PrepareWeb(); err != nil {
		log.Fatalf("vpn-panel: %v", err)
	}

	app.Start()
}

func applyMemoryLimit() {
	if os.Getenv("GOMEMLIMIT") != "" {

		log.Printf("vpn-panel: мягкий предел памяти задан окружением, расчёт пропущен")
		return
	}
	soft, hard, ok := cgroupstat.ApplySoftLimit()
	if !ok {
		log.Printf("vpn-panel: у группы процесса нет предела памяти — мягкий предел не ставится")
		return
	}
	log.Printf("vpn-panel: мягкий предел памяти %d МиБ (%.0f %% от предела группы %d МиБ)",
		soft>>20, cgroupstat.SoftRatio*100, hard>>20)

	if hard < cgroupstat.MinComfortable {
		log.Printf("vpn-panel: панели тесно — предел группы %d МиБ ниже %d МиБ, возможны перезапуски по памяти",
			hard>>20, cgroupstat.MinComfortable>>20)
	}
}
