package common

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"taiyi/config"
)

func ParsePort(value interface{}) ([]int, error, []string) {
	var ports []int
	var ranges []string
	var errorPorts []string

	// 去重
	ExistPorts := make(map[int]struct{})
	chanPorts := make(chan int, 300)
	var aliveWg sync.WaitGroup
	go func() {
		for port := range chanPorts {
			if _, ok := ExistPorts[port]; !ok {
				ExistPorts[port] = struct{}{}
			}
			aliveWg.Done()
		}
	}()

	switch i := value.(type) {
	case nil:
		return nil, errors.New(fmt.Sprintf("port:%T", i)), nil
	case string:
		ranges = strings.Split(value.(string), ",")
	case []string:
		ranges = value.([]string)
	}

	for _, r := range ranges {
		r = strings.TrimSpace(r)
		switch r {
		case "top100":
			tmp, _, _ := ParsePort(config.Top100Ports)
			for _, v := range tmp {
				aliveWg.Add(1)
				chanPorts <- v
			}
		case "top1000":
			tmp, _, _ := ParsePort(config.Top1000Ports)
			for _, v := range tmp {
				aliveWg.Add(1)
				chanPorts <- v
			}
		default:
			if strings.Contains(r, "-") {
				parts := strings.Split(r, "-")
				if len(parts) != 2 {
					errorPorts = append(errorPorts, r)
					continue
				}
				p1, err := strconv.Atoi(parts[0])
				p2, err := strconv.Atoi(parts[1])
				if err != nil ||
					p1 > p2 ||
					p1 < 0 || p1 > 65535 ||
					p2 < 0 || p2 > 65535 {
					errorPorts = append(errorPorts, r)
					continue
				}
				// true port
				for i := p1; i <= p2; i++ {
					//ports = append(ports, i)
					aliveWg.Add(1)
					chanPorts <- i
				}
			} else {
				port, err := strconv.Atoi(r)
				if err != nil ||
					port < 0 || port > 65535 {
					errorPorts = append(errorPorts, r)
					continue
				} else {
					//ports = append(ports, port)
					aliveWg.Add(1)
					chanPorts <- port
				}
			}
		}
	}

	aliveWg.Wait()
	close(chanPorts)

	for port, _ := range ExistPorts {
		ports = append(ports, port)
	}

	return ports, nil, errorPorts
}
