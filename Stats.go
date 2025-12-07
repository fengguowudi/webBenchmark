package main

import (
	"fmt"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	netstat "github.com/shirou/gopsutil/net"
	"math"
	URL "net/url"
	"strings"
	"time"
)

func showStat() {
	initialNetCounter, _ := netstat.IOCounters(true)
	lastCounters := buildCounterMap(initialNetCounter)
	lastSampleTime := time.Now()
	iplist := ""
	if customIP != nil && len(customIP) > 0 {
		iplist = customIP.String()
	} else {
		u, _ := URL.Parse(TargetUrl)
		iplist = strings.Join(nslookup(u.Hostname(), "8.8.8.8"), ",")
	}

	for true {
		percent, _ := cpu.Percent(time.Second, false)
		memStat, _ := mem.VirtualMemory()
		netCounter, _ := netstat.IOCounters(true)
		loadStat, _ := load.Avg()
		now := time.Now()
		elapsedSeconds := now.Sub(lastSampleTime).Seconds()
		if elapsedSeconds <= 0 {
			elapsedSeconds = 1
		}

		fmt.Fprintf(TerminalWriter, "URL:%s\n", TargetUrl)
		fmt.Fprintf(TerminalWriter, "IP:%s\n", iplist)

		fmt.Fprintf(TerminalWriter, "CPU:%.3f%% \n", percent)
		fmt.Fprintf(TerminalWriter, "Memory:%.3f%% \n", memStat.UsedPercent)
		fmt.Fprintf(TerminalWriter, "Load:%.3f %.3f %.3f\n", loadStat.Load1, loadStat.Load5, loadStat.Load15)
		for i := 0; i < len(netCounter); i++ {
			if netCounter[i].BytesRecv == 0 && netCounter[i].BytesSent == 0 {
				continue
			}
			prevCounter, ok := lastCounters[netCounter[i].Name]
			if !ok {
				prevCounter = netCounter[i]
			}
			RecvBytes := float64(netCounter[i].BytesRecv - prevCounter.BytesRecv)
			SendBytes := float64(netCounter[i].BytesSent - prevCounter.BytesSent)
			RecvSpeed := RecvBytes / elapsedSeconds
			SendSpeed := SendBytes / elapsedSeconds
			fmt.Fprintf(TerminalWriter, "Nic:%v,Recv %s(%s/s),Send %s(%s/s)\n", netCounter[i].Name,
				readableBytes(float64(netCounter[i].BytesRecv)),
				readableBytes(RecvSpeed),
				readableBytes(float64(netCounter[i].BytesSent)),
				readableBytes(SendSpeed))
		}
		lastCounters = buildCounterMap(netCounter)
		lastSampleTime = now
		TerminalWriter.Clear()
		TerminalWriter.Print()
		time.Sleep(1 * time.Second)
	}
}

func buildCounterMap(counters []netstat.IOCountersStat) map[string]netstat.IOCountersStat {
	counterMap := make(map[string]netstat.IOCountersStat, len(counters))
	for i := 0; i < len(counters); i++ {
		counterMap[counters[i].Name] = counters[i]
	}
	return counterMap
}

func readableBytes(bytes float64) (expression string) {
	if bytes == 0 {
		return "0B"
	}
	var i = math.Floor(math.Log(bytes) / math.Log(1024))
	var sizes = []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	return fmt.Sprintf("%.3f%s", bytes/math.Pow(1024, i), sizes[int(i)])
}
