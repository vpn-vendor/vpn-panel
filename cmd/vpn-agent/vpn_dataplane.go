package main

import (
	"context"
	"log"
	"time"
)

type dataSample struct {
	at              bootInstant
	echoOut, echoIn int64
	payRx, payTx    int64
}

const dataRestartBudget = 2

func addSample(samples []dataSample, s dataSample, staleSec int64) []dataSample {
	if n := len(samples); n > 0 {
		p := samples[n-1]
		if s.echoOut < p.echoOut || s.echoIn < p.echoIn || s.payRx < p.payRx || s.payTx < p.payTx {
			samples = nil
		}
	}
	samples = append(samples, s)
	cut := 0
	for i := range samples {
		if int64(s.at.Sub(samples[i].at)/time.Second) >= staleSec {
			cut = i
		}
	}
	return samples[cut:]
}

func dataEvidence(samples []dataSample, staleSec int64) (dead, suspect bool) {
	if len(samples) < 2 {
		return false, false
	}
	first, last := samples[0], samples[len(samples)-1]
	if int64(last.at.Sub(first.at)/time.Second) < staleSec {
		return false, false
	}
	if last.echoOut > first.echoOut {
		return last.echoIn == first.echoIn, false
	}
	return false, last.payTx > first.payTx && last.payRx == first.payRx
}

func (v *vpnApplier) observeData(s dataSample, staleSec int64) (dead, suspect bool) {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	if n := len(v.watch.dataSamples); n > 0 && s.echoIn > v.watch.dataSamples[n-1].echoIn {
		v.watch.DataRestarts = 0
	}
	v.watch.dataSamples = addSample(v.watch.dataSamples, s, staleSec)
	dead, suspect = dataEvidence(v.watch.dataSamples, staleSec)
	v.watch.DataDead, v.watch.DataSuspect = dead, suspect
	return dead, suspect
}

func (v *vpnApplier) firewallEcho() (out, in int64, ok bool) {
	if v.firewall == nil {
		return 0, 0, false
	}
	return v.firewall.echoCounters()
}

func (v *vpnApplier) forgetData() {
	v.watchMu.Lock()
	defer v.watchMu.Unlock()
	v.watch.dataSamples, v.watch.DataDead, v.watch.DataSuspect = nil, false, false
}

func (v *vpnApplier) restartForData(ctx context.Context, st vpnState) {
	v.watchMu.Lock()
	v.watch.DataRestarts++
	n := v.watch.DataRestarts
	v.watch.dataSamples, v.watch.DataDead = nil, false
	v.saveWatchdogMemory()
	v.watchMu.Unlock()
	log.Printf("vpn: tunnel is connected but data does not pass, full restart %d of %d", n, dataRestartBudget)
	v.bringDown(&st)
	if _, aerr := v.bringUp(&st); aerr != nil {
		log.Printf("vpn: restart for data failed: %s", aerr.Message)
		return
	}
	if v.waitHandshake(ctx, &st) {
		if _, aerr := v.applyBlackServices(&st); aerr != nil {
			log.Printf("vpn: services not restored after restart for data: %s", aerr.Message)
		}
	}
}
