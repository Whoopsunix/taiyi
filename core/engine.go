package core

import (
	"context"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"github.com/tidwall/gjson"
	"regexp"
	"strconv"
	"sync"
	"taiyi/common"
	"taiyi/plugins/portScan"
	"time"
	"unicode/utf8"
)

type Addr struct {
	ip   string
	port uint
}

func NewAddr(ip string, port uint) *Addr {
	return &Addr{
		ip:   ip,
		port: port,
	}
}

type Engine struct {
	CliInfo      *common.CliInfo
	TaskIPs      []string
	TaskPorts    []int
	aLiveIps     []string
	Banners      *gjson.Result
	PortInfoList []*common.PortInfo

	TaskChan    chan Addr
	ResultChan  chan *common.PortInfo
	WorkerCount int
	Wg          *sync.WaitGroup
	Ctx         context.Context
	Ticker      *time.Ticker
	Bar         *progressbar.ProgressBar
	FinishNum   int
}

func NewEngine(CliInfo *common.CliInfo) *Engine {
	return &Engine{
		TaskChan:    make(chan Addr, CliInfo.Threads),
		ResultChan:  make(chan *common.PortInfo, CliInfo.Threads),
		WorkerCount: CliInfo.Threads,
		Wg:          &sync.WaitGroup{},
		CliInfo:     CliInfo,
		FinishNum:   0,
	}
}

func (e *Engine) Parse() error {
	// ip parse
	ips, err, errorIps := common.ParseIp(e.CliInfo.Ips)
	if err != nil {
		return err
	}
	if errorIps != nil {
		e.CliInfo.Warn(errorIps)
	}
	// port parse
	ports, err, errorPorts := common.ParsePort(e.CliInfo.Ports)
	if err != nil {
		return err
	}
	if errorPorts != nil {
		e.CliInfo.Warn(errorPorts)
	}
	e.TaskIPs = ips
	e.TaskPorts = ports
	return nil
}

func (e *Engine) Start() {
	e.Wg.Add(e.WorkerCount)
	// 计时器 进度条
	e.Ticker = time.NewTicker(time.Second * 1)
	e.Bar = progressbar.Default(int64(len(e.aLiveIps) * len(e.TaskPorts)))
	go func(t *time.Ticker) {
		for {
			<-t.C
			e.Bar.Set(e.FinishNum)
			fmt.Print("\n")
			time.Sleep(time.Second * 5)
		}
	}(e.Ticker)

	go e.Scheduler()

	// aLiveIps&TaskPorts -> Addr
	var addr Addr
	for _, ip := range e.aLiveIps {
		for _, port := range e.TaskPorts {
			addr.ip = ip
			addr.port = uint(port)
			select {
			case <-e.Ctx.Done():
				for {
					if len(e.TaskChan) > 0 {
						<-e.TaskChan
					}
				}
				//return
			default:
				e.TaskChan <- addr
			}
		}
	}

	//e.Saver()
	//close(e.ResultChan)
	close(e.TaskChan)

	e.Ticker.Stop()
	e.Bar.Close()
}

// test
func (e *Engine) Saver() {
	for portInfo := range e.ResultChan {
		e.PortInfoList = append(e.PortInfoList, portInfo)
	}

}

// Scheduler 扫描任务创建
func (e *Engine) Scheduler() {
	for i := 0; i < e.WorkerCount; i++ {
		e.worker()
	}
}

func (e *Engine) worker() {
	//var portInfo *common.PortInfo
	go func() {
		defer e.Wg.Done()
		for addr := range e.TaskChan {
			switch e.CliInfo.Technique {
			case "sv":
				e.Scanner(addr)
			case "ss":
				e.SimpleScanner(addr)
			}
			e.FinishNum += 1
		}
	}()
}

func (e *Engine) SimpleScanner(addr Addr) {
	scanIp := addr.ip
	scanPort := addr.port
	portInfo := common.PortInfo{}
	protocol := "tcp"
	err, rec := portScan.NewSend(protocol, []byte(""), scanIp, scanPort)
	// port not open
	if err != nil {
		if err.Error() == "connect err" && rec == nil {
			return
		}
	}
	e.CliInfo.Log(fmt.Sprintf("%s:%d open", scanIp, scanPort))
	e.PortInfoList = append(e.PortInfoList, &portInfo)
}

func (e *Engine) Scanner(addr Addr) {
	scanIp := addr.ip
	scanPort := addr.port
	banners := e.Banners

	aliveFlag := false
	portInfo := common.PortInfo{}
	reg := false
	banners.ForEach(func(key, banner gjson.Result) bool {
		protocol := banner.Get("protocol").Str
		if key.Num == 0 {
			err, rec := portScan.NewSend(protocol, []byte(""), scanIp, scanPort)

			// 正则debug
			//fmt.Println("rec: ", rec)
			//fmt.Println("rec: ", string(rec))
			//s2 := "^.\x00\x00\x00[\\s\\S]..Host .* is not allowed to connect to this MySQL server$"
			//fmt.Println("s2: ", reflect.TypeOf(s2))
			//reg, _ = regexp.Match(s2, rec)
			//fmt.Println("reg4: ", reg)

			// port not open
			if err != nil {
				if err.Error() == "connect err" && rec == nil {
					return false
				}
			}
			e.CliInfo.Log(fmt.Sprintf("%s:%d open", scanIp, scanPort))

			aliveFlag = true
			portInfo.Ip = scanIp
			portInfo.Port = scanPort

			matches := banner.Get("matches")
			matches.ForEach(func(key, match gjson.Result) bool {
				pattern := match.Get("pattern")
				s, _ := strconv.Unquote(pattern.Raw)
				reg, _ = regexp.Match(s, rec)

				// 正确识别
				if reg == true {
					portInfo.Pattern = pattern.Raw
					portInfo.Name = match.Get("name").Str
					portInfo.VendorProductName = match.Get("versioninfo.vendorproductname").Str
					//fmt.Println()
					//fmt.Println("rec: ", rec)
					//fmt.Println("scanport: ", scanPort)
					//fmt.Println("probename: ", banner.Get("probename"))
					//fmt.Println("payload: ", banner.Get("probestring").Raw)
					//fmt.Println("name: ", match.Get("name"))
					//fmt.Println("pattern: ", pattern.Raw)
					//fmt.Println()
					return false
				}
				return true
			})
			if reg == true {
				//fmt.Println(scanIp, "  ", scanPort)
				//e.CliInfo.Log(fmt.Sprintf(scanIp, "  ", scanPort))
				return false
			}
		}

		//调试模拟 if key.Num == 20{

		// 端口是否在预设端口内
		preset := false
		ports := banner.Get("ports")
		ports_list := common.GetPorts(ports)
		for _, port := range ports_list {
			if uint(port) == scanPort {
				preset = true
				break
			}
		}

		// 为预设端口，发送payload
		if preset {
			probestring := banner.Get("probestring").Raw
			s, _ := strconv.Unquote(probestring)
			_, rec := portScan.NewSend(protocol, []byte(s), scanIp, scanPort)

			// 正则匹配
			//reg := false
			matches := banner.Get("matches")
			matches.ForEach(func(key, match gjson.Result) bool {
				// return nil break
				if rec == nil {
					return false
				}
				pattern := match.Get("pattern")
				s, _ := strconv.Unquote(pattern.Raw)
				reg, _ = regexp.Match(s, rec)

				// identify success
				if reg == true {
					portInfo.Pattern = pattern.Raw
					portInfo.Name = match.Get("name").Str
					portInfo.VendorProductName = match.Get("versioninfo.vendorproductname").Str
					//fmt.Println()
					//fmt.Println("rec: ", rec)
					//fmt.Println("scanport: ", scanPort)
					//fmt.Println("probename: ", banner.Get("probename"))
					//fmt.Println("payload: ", banner.Get("probestring").Raw)
					//fmt.Println("name: ", match.Get("name"))
					//fmt.Println("pattern: ", pattern.Raw)
					//fmt.Println()
					return false
				}
				return true
			})
			//match, _ := regexp.Match("^\x05\x00\\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00...$", []byte(str))
			if reg == true {
				return false
			}

		}
		return true
	})

	if reg {
		e.CliInfo.LogSpecial(fmt.Sprintf("%+v", portInfo))
	} else if aliveFlag && !reg && e.CliInfo.Powerful {
		// 将portInfo信息传入，执行强扫描
		portInfo = *e.PowerfulScanner(&portInfo)
	}

	if aliveFlag {
		e.PortInfoList = append(e.PortInfoList, &portInfo)
	}

}

func convert(src string) string {
	var dst string = ""
	for i, r := range src {
		var v string = ""
		if r == utf8.RuneError {
			v = string(src[i])
		} else {
			v = string(r)
		}
		dst += string(v)
	}
	return dst
}

// PowerfulScanner 强扫描补充
func (e *Engine) PowerfulScanner(portInfo *common.PortInfo) *common.PortInfo {
	scanIp := portInfo.Ip
	scanPort := portInfo.Port
	banners := e.Banners

	reg := false
	banners.ForEach(func(key, banner gjson.Result) bool {
		// 端口是否在预设端口内
		preset := false
		ports := banner.Get("ports")
		ports_list := common.GetPorts(ports)
		for _, port := range ports_list {
			if uint(port) == scanPort {
				preset = true
				break
			}
		}
		// 未使用过的payload
		if !preset {
			protocol := banner.Get("protocol").Str
			probestring := banner.Get("probestring").Raw
			s, _ := strconv.Unquote(probestring)
			_, rec := portScan.NewSend(protocol, []byte(s), scanIp, scanPort)

			// 正则匹配
			matches := banner.Get("matches")
			matches.ForEach(func(key, match gjson.Result) bool {
				// return nil break
				if rec == nil {
					return false
				}
				pattern := match.Get("pattern")
				s, _ := strconv.Unquote(pattern.Raw)
				reg, _ = regexp.Match(s, rec)

				// identify success
				if reg == true {
					portInfo.Pattern = pattern.Raw
					portInfo.Name = match.Get("name").Str
					portInfo.VendorProductName = match.Get("versioninfo.vendorproductname").Str
					return false
				}
				return true
			})
			//match, _ := regexp.Match("^\x05\x00\\r\x03\x10\x00\x00\x00\x18\x00\x00\x00....\x04\x00\x01\x05\x00...$", []byte(str))
			if reg == true {
				return false
			}
		}
		return true

	})
	if reg {
		e.CliInfo.LogSpecial(fmt.Sprintf("%+v", portInfo))
	}
	return portInfo
}
