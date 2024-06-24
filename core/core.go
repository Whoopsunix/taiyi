package core

import (
	"context"
	"errors"
	"fmt"
	"github.com/tidwall/gjson"
	"os"
	"os/signal"
	"taiyi/common"
	"taiyi/config"
	"taiyi/plugins/host"
)

func Start(ctx context.Context) {
	// get cli parameters
	cliInfos := common.NewCliInfo()
	//flag.Parse() // test
	var err error

	common.Info("Good luck!")
	engine := NewEngine(cliInfos)
	err = engine.Parse()
	// parsing parameters
	if err != nil {
		common.Warn(err.Error())
	}

	go engine.SafeQuit()

	engine.Ctx = ctx
	switch cliInfos.Technique {
	case "sp":
		// ping scan
		err := engine.pingControl()
		if err != nil {
			break
		}
	case "ss":
		// port scan
		err := engine.pingControl()
		if err != nil {
			break
		}
		engine.portControl()
	case "sv":
		// port scan and banner identify
		err := engine.pingControl()
		if err != nil {
			break
		}
		engine.portBannerControl()
	}
	// export to file -o
	common.InfoSpecial("saving...")
	engine.ExportControl()
	common.InfoSpecial("finish!!!")
}

// portControl control by -t ss
func (e *Engine) portControl() {
	common.Info("begin port scan")
	e.Start()
	select {
	case <-e.Ctx.Done():
		//todo fmt.Println("over")
	default:
		e.Wg.Wait()
	}
	common.InfoSpecial(fmt.Sprintf("[%d] open ports were found!", len(e.PortInfoList)))

}

// portBannerControl control by -t sv
func (e *Engine) portBannerControl() {
	common.Info("begin port scan")
	common.Info("loading banners")
	content, err := config.Asset("nmap.json")
	if err != nil {
		common.Warn("banners loading failed")
		// 尝试无指纹端口扫描
		e.portControl()
		return
	}
	data := string(content)
	banners := gjson.Get(data, "@this")
	e.Banners = &banners

	e.Start()
	select {
	case <-e.Ctx.Done():
		//todo fmt.Println("over")
	default:
		e.Wg.Wait()
	}
	common.InfoSpecial(fmt.Sprintf("[%d] open ports were found!", len(e.PortInfoList)))
}

// pingControl control by -t sp
func (e *Engine) pingControl() error {
	if !e.CliInfo.NoPing {
		common.Info("begin host discovery")
		e.aLiveIps = host.Start(e.TaskIPs)
		if e.aLiveIps == nil {
			common.Warn("no online hosts are discovered")
			return errors.New("no online hosts are discovered")
		} else {
			common.InfoSpecial(fmt.Sprintf("[%d/%d] online hosts were found!", len(e.aLiveIps), len(e.TaskIPs)))
		}
	} else {
		common.Info("skip host discovery")
		e.aLiveIps = e.TaskIPs
	}
	common.Info("task ips：")
	common.InfoSpecial(e.aLiveIps)
	return nil
}

// ExportControl control by -o
func (e *Engine) ExportControl() {
	if e.CliInfo.Export == "no" {
		return
	}
	var err error
	if e.CliInfo.Export == "xlsx" || e.CliInfo.Export == "all" {
		err = common.Export2xlsx(e.CliInfo.FileName, e.PortInfoList)
		if err != nil {
			common.Warn("export to xlsx failed")
		} else {
			common.Info("export to xlsx success")
		}
	}
	if e.CliInfo.Export == "txt" || e.CliInfo.Export == "all" {
		err = common.Export2txt(e.CliInfo.FileName, e.PortInfoList)
		if err != nil {
			common.Warn("export to txt failed")
		} else {
			common.Info("export to txt success")
		}
	}
}

// SafeQuit capture ctr+c
func (e *Engine) SafeQuit() {
	if e.CliInfo.Export == "no" {
		return
	}
	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt)
	select {
	case sig := <-sigChan:
		common.Warn("safe quit...", sig)
		e.ExportControl()
		os.Exit(0)
	}
}
