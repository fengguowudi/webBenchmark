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

		fmt.Fprintf(TerminalWriter, "URL:%s\n", TargetUrl)
		fmt.Fprintf(TerminalWriter, "IP:%s\n", iplist)

		fmt.Fprintf(TerminalWriter, "CPU:%.3f%% \n", percent)
		fmt.Fprintf(TerminalWriter, "Memory:%.3f%% \n", memStat.UsedPercent)
		fmt.Fprintf(TerminalWriter, "Load:%.3f %.3f %.3f\n", loadStat.Load1, loadStat.Load5, loadStat.Load15)
		for i := 0; i < len(netCounter); i++ {
			if netCounter[i].BytesRecv == 0 && netCounter[i].BytesSent == 0 {
				continue
			}
			RecvBytes := float64(netCounter[i].BytesRecv - initialNetCounter[i].BytesRecv)
			SendBytes := float64(netCounter[i].BytesSent - initialNetCounter[i].BytesSent)
			//if RecvBytes > 1000 {
			//	SpeedIndex++
			//	pair := speedPair{
			//		index: SpeedIndex,
			//		speed: RecvBytes,
			//	}
			//	SpeedQueue.PushBack(pair)
			//	if SpeedQueue.Len() > 60 {
			//		SpeedQueue.Remove(SpeedQueue.Front())
			//	}
			//	var x []float64
			//	var y []float64
			//	x = make([]float64, 60)
			//	y = make([]float64, 60)
			//	var point = 0
			//	for item := SpeedQueue.Front(); item != nil; item = item.Next() {
			//		spdPair := item.Value.(speedPair)
			//		x[point] = float64(spdPair.index)
			//		y[point] = spdPair.speed
			//		point++
			//	}
			//	_, b := LeastSquares(x, y)
			//	log.Printf("Speed Vertical:%.3f\n", b)
			//}
			fmt.Fprintf(TerminalWriter, "Nic:%v,Recv %s(%s/s),Send %s(%s/s)\n", netCounter[i].Name,
				readableBytes(float64(netCounter[i].BytesRecv)),
				readableBytes(RecvBytes),
				readableBytes(float64(netCounter[i].BytesSent)),
				readableBytes(SendBytes))
		}
		initialNetCounter = netCounter
		TerminalWriter.Clear()
		TerminalWriter.Print()
		time.Sleep(1 * time.Second)
	}
}

func readableBytes(bytes float64) (expression string) {
	if bytes == 0 {
		return "0B"
	}
	var i = math.Floor(math.Log(bytes) / math.Log(1024))
	var sizes = []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	return fmt.Sprintf("%.3f%s", bytes/math.Pow(1024, i), sizes[int(i)])
}
