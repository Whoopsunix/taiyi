package host

import (
	"bytes"
	"fmt"
	"golang.org/x/net/icmp"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"taiyi/common"
	"time"
)

var (
	OS         = runtime.GOOS
	aliveWg    sync.WaitGroup
	ExistHosts = make(map[string]struct{})
	LiveIps    []string
)

func Start(ips []string) []string {
	chanHosts := make(chan string, 10)

	go func() {
		for host := range chanHosts {
			if _, ok := ExistHosts[host]; !ok {
				ExistHosts[host] = struct{}{}
			}
			aliveWg.Done()
		}
	}()

	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err == nil {
		// syn detection
		IcmpScan2(ips, conn, chanHosts)
		common.Warn("please using by sudo")
	} else {
		conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", 6*time.Second)
		if conn != nil || err == nil {
			go conn.Close()
			IcmpScan(ips, chanHosts)
		} else {
			PingScan(ips, chanHosts)
		}
	}

	aliveWg.Wait()
	close(chanHosts)

	// make sure in ips
	for _, ip := range ips {
		if _, ok := ExistHosts[ip]; ok {
			LiveIps = append(LiveIps, ip)
		}
	}

	return LiveIps

}

func PingScan(hostLists []string, chanHosts chan string) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50) // unsafe.Sizeof() == 0
	for _, host := range hostLists {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if execPing(host) {
				aliveWg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

func execPing(ip string) bool {
	var cmd *exec.Cmd

	if OS == "windows" {
		cmd = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false")
	} else if OS == "linux" {
		// todo check
		cmd = exec.Command("/bin/sh", "-c", "ping -c 1 -w 1 "+ip+" >/dev/null && echo true || echo false")
	} else if OS == "darwin" {
		// todo bug
		cmd = exec.Command("/bin/sh", "-c", "ping -c 1 -W 1 "+ip+" >/dev/null && echo true || echo false")
	}

	csbuff := bytes.Buffer{}
	cmd.Stdout = &csbuff
	//cmd.Stderr = &csbuff

	// inherit father thread status
	err := cmd.Run()
	if err != nil {
		return false
	}
	if strings.Contains(csbuff.String(), "true") {
		return true
	} else {
		return false
	}
}

func IcmpScan2(hostLists []string, conn *icmp.PacketConn, chanHosts chan string) {
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	// send syn to target ip
	for _, host := range hostLists {
		addr, _ := net.ResolveIPAddr("ip", host)
		msg := makeMsg(host)
		conn.WriteTo(msg, addr)
	}

	// Constant reading from coon
	flag := false
	go func() {
		for {
			if flag {
				return
			}
			b := make([]byte, 100)
			_, addr, _ := conn.ReadFrom(b)
			if addr != nil {
				aliveWg.Add(1)
				chanHosts <- addr.String()
			}

		}
	}()

	//easy dynamic time setting
	startTime := time.Now()
	span := time.Second * 6
	for {
		span = time.Duration(len(hostLists)/256+1) * 6 * time.Second
		if time.Now().Sub(startTime) > span {
			flag = true
			break
		}
	}
}

func IcmpScan(hostLists []string, chanHosts chan string) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 1000) // unsafe.Sizeof() == 0
	for _, host := range hostLists {
		wg.Add(1)
		limiter <- struct{}{}
		go func(host string) {
			if connect(host) {
				aliveWg.Add(1)
				chanHosts <- host
			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
	close(limiter)
}

func connect(host string) bool {
	conn, err := net.DialTimeout("ip4:icmp", host, 6*time.Second)
	if err != nil {
		return false
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()
	// set deadline so we don't wait forever
	if err := conn.SetDeadline(time.Now().Add(6 * time.Second)); err != nil {
		return false
	}
	msg := makeMsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}
	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}
	//if msg[20+5] == 13 {
	//	fmt.Println("Identifier matches")
	//}
	//if msg[20+7] == 37 {
	//	fmt.Println("Sequence matches")
	//}
	//if msg[20+8] == 99 {
	//	fmt.Println("Custom data matches")
	//}
	return true
}

func makeMsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

func checkSum(msg []byte) uint16 {
	sum := 0
	len := len(msg)
	for i := 0; i < len-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if len%2 == 1 {
		sum += int(msg[len-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)
	var answer uint16 = uint16(^sum)
	return answer
}

func checkError(err error) {
	if err != nil {
		fmt.Fprint(os.Stderr, "Fatal error:", err.Error())
		os.Exit(1)
	}
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}
