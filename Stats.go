package main

import (
	"context"
	"fmt"
	"net"
	neturl "net/url"
	"strings"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	netstat "github.com/shirou/gopsutil/net"
)

func showStat(ctx context.Context) {
	initialCounters, _ := netstat.IOCounters(true)
	lastCounters := buildCounterMap(initialCounters)
	lastSampleTime := time.Now()
	lastTarget := ""
	ipList := ""
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		target := currentTargetURL()
		if target != lastTarget {
			lastTarget = target
			if len(customIP) > 0 {
				ipList = customIP.String()
			} else {
				ipList = resolveTarget(ctx, target)
			}
		}

		cpuValues, _ := cpu.Percent(0, false)
		cpuPercent := 0.0
		if len(cpuValues) > 0 {
			cpuPercent = cpuValues[0]
		}
		memory, _ := mem.VirtualMemory()
		memoryPercent := 0.0
		if memory != nil {
			memoryPercent = memory.UsedPercent
		}
		loadAverage, _ := load.Avg()

		now := time.Now()
		elapsed := now.Sub(lastSampleTime).Seconds()
		if elapsed <= 0 {
			elapsed = 1
		}
		lastSampleTime = now

		fmt.Fprintf(terminalWriter, "URL:%s\nIP:%s\n", target, ipList)
		fmt.Fprintf(terminalWriter, "CPU:%.3f%% Memory:%.3f%%\n", cpuPercent, memoryPercent)
		if loadAverage == nil {
			fmt.Fprintln(terminalWriter, "Load: unavailable")
		} else {
			fmt.Fprintf(terminalWriter, "Load:%.3f %.3f %.3f\n", loadAverage.Load1, loadAverage.Load5, loadAverage.Load15)
		}

		counters, _ := netstat.IOCounters(true)
		for _, counter := range counters {
			if counter.BytesRecv == 0 && counter.BytesSent == 0 {
				continue
			}
			previous, ok := lastCounters[counter.Name]
			if !ok {
				previous = counter
			}
			recvBytes := counterDelta(counter.BytesRecv, previous.BytesRecv)
			sentBytes := counterDelta(counter.BytesSent, previous.BytesSent)
			fmt.Fprintf(terminalWriter, "Nic:%s Recv %s(%s/s) Send %s(%s/s)\n",
				counter.Name,
				readableBytes(float64(counter.BytesRecv)),
				readableBytes(float64(recvBytes)/elapsed),
				readableBytes(float64(counter.BytesSent)),
				readableBytes(float64(sentBytes)/elapsed))
		}
		lastCounters = buildCounterMap(counters)

		terminalWriter.Clear()
		terminalWriter.Print()
	}
}

func resolveTarget(ctx context.Context, rawURL string) string {
	parsed, err := neturl.Parse(rawURL)
	if err != nil || parsed.Hostname() == "" {
		return "unknown"
	}
	lookupContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(lookupContext, parsed.Hostname())
	if err != nil {
		return "unknown"
	}
	return strings.Join(addresses, ",")
}

func buildCounterMap(counters []netstat.IOCountersStat) map[string]netstat.IOCountersStat {
	counterMap := make(map[string]netstat.IOCountersStat, len(counters))
	for _, counter := range counters {
		counterMap[counter.Name] = counter
	}
	return counterMap
}

func counterDelta(current, previous uint64) uint64 {
	if current < previous {
		return current
	}
	return current - previous
}

func readableBytes(bytes float64) string {
	if bytes <= 0 {
		return "0B"
	}
	sizes := [...]string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	unit := 0
	for bytes >= 1024 && unit < len(sizes)-1 {
		bytes /= 1024
		unit++
	}
	return fmt.Sprintf("%.3f%s", bytes, sizes[unit])
}
