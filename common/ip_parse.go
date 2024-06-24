package common

import (
	"errors"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
)

var (
	errorIps []string
)

func ParseIp(value string) ([]string, error, []string) {
	var lines []string
	var ips []string

	err, lines := GetLinesFromFile(value)
	// 不是文件需要处理
	if err != nil {
		ranges := strings.Split(value, ",")
		for _, r := range ranges {
			r = strings.TrimSpace(r)
			lines = append(lines, r)
		}
	}

	// 去重
	ExistIps := make(map[string]struct{})
	chanIps := make(chan string, 300)
	var aliveWg sync.WaitGroup
	go func() {
		for ip := range chanIps {
			if _, ok := ExistIps[ip]; !ok {
				ExistIps[ip] = struct{}{}
			}
			aliveWg.Done()
		}
	}()

	for _, line := range lines {
		// 范围解析
		if strings.Contains(line, "/") {
			ip, ipNet, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); ipRanges(ip) {
				ipStr := ip.String()
				last := strings.Split(ipStr, ".")
				if last[len(last)-1] <= "0" || last[len(last)-1] >= "255" {
					continue
				}
				aliveWg.Add(1)
				chanIps <- ipStr
			}

		} else if strings.Contains(line, "-") {
			parts := strings.Split(line, "-")
			if len(parts) != 2 {
				continue
			}

			ip := IsIpv4(parts[0])
			if ip == nil {
				continue
			}

			ipNum, _ := IPString2Long(ip.String())
			right, err := strconv.Atoi(parts[1])
			parts2 := strings.Split(parts[0], ".")
			left, err := strconv.Atoi(parts2[3])
			if err != nil || left < 1 || right > 254 {
				continue
			}
			for i := left - 1; i <= right-left; i++ {
				ipStr, _ := Long2IPString(ipNum + uint(i))
				aliveWg.Add(1)
				chanIps <- ipStr
			}

		} else {
			// isipv4
			ip := IsIpv4(line)
			if ip != nil {
				last := strings.Split(line, ".")
				num, _ := strconv.Atoi(last[len(last)-1])
				if num <= 0 || num >= 255 {
					continue
				}
				aliveWg.Add(1)
				chanIps <- ip.String()
				continue
			}
		}

		//else if cname, _ := net.LookupCNAME(line); cname != "" {
		//	// 解析ip地址
		//	ns, err := net.LookupHost(line)
		//	if err != nil {
		//
		//	}
		//
		//	// 反向解析
		//	dnsname, _ := net.LookupAddr(line)
		//	fmt.Println("hostname:", dnsname)
		//
		//	// 域名解析控制判断
		//	switch {
		//	case cname != "":
		//		fmt.Println("cname:", cname)
		//		if len(ns) != 0 {
		//			fmt.Println("vips:")
		//			for _, n := range ns {
		//				fmt.Println("ip:", n)
		//			}
		//		}
		//	case len(ns) != 0:
		//		for _, n := range ns {
		//			fmt.Println("ip:", n)
		//		}
		//	}
		//}

	}

	//fmt.Println(lines)
	aliveWg.Wait()
	close(chanIps)

	for ip, _ := range ExistIps {
		ips = append(ips, ip)
	}

	return ips, nil, errorIps
}

func IsIpv4(value string) net.IP {
	ip := net.ParseIP(value)
	if ip == nil {
		errorIps = append(errorIps, value)
	}
	return ip
}

// 用于 / 格式的ip递增
func ipRanges(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		//fmt.Println(ip)
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// IPString2Long 把ip字符串转为数值
func IPString2Long(ip string) (uint, error) {
	b := net.ParseIP(ip).To4()
	if b == nil {
		return 0, errors.New("invalid ipv4 format")
	}
	return uint(b[3]) | uint(b[2])<<8 | uint(b[1])<<16 | uint(b[0])<<24, nil
}

// Long2IPString 把数值转为ip字符串
func Long2IPString(i uint) (string, error) {
	if i > math.MaxUint32 {
		return "", errors.New("beyond the scope of ipv4")
	}
	ip := make(net.IP, net.IPv4len)
	ip[0] = byte(i >> 24)
	ip[1] = byte(i >> 16)
	ip[2] = byte(i >> 8)
	ip[3] = byte(i)
	return ip.String(), nil
}
