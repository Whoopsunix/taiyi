package common

import (
	"flag"
	"fmt"
	"strings"
)

// parse ',' by using slice
type sliceValue []string

func newSliceValue(vals []string, p *[]string) *sliceValue {
	*p = vals
	return (*sliceValue)(p)
}

func (s *sliceValue) Set(val string) error {
	*s = sliceValue(strings.Split(val, ","))
	return nil
}

func (s *sliceValue) Get() interface{} {
	return []string(*s)
}

func (s *sliceValue) String() string {
	return strings.Join([]string(*s), ",")
}

type Value interface {
	String() string
	Set(string) error
}

var (
	ips       string
	ports     string
	noPing    bool
	threads   int
	technique string
	fileName  string
	export    string
	debug     bool
	powerful  bool
)

type CliInfo struct {
	Ips       string
	Ports     string
	NoPing    bool
	Threads   int
	Technique string
	FileName  string
	Export    string
	Debug     bool
	Powerful  bool
}

func NewCliInfo() *CliInfo {
	return &CliInfo{
		Ips:       ips,
		Ports:     ports,
		NoPing:    noPing,
		Threads:   threads,
		Technique: technique,
		FileName:  fileName,
		Export:    export,
		Debug:     debug,
		Powerful:  powerful,
	}
}

func init() {
	Version()
	flag.StringVar(&ips, "i", "", "set ip,eg. 192.168.0.1/24,192.168.0.1-10,ip.txt")
	flag.StringVar(&ports, "p", "top100", "set port,eg. 80,110-120,top100,top1000")
	flag.StringVar(&technique, "t", "sv", "scan technique")
	flag.IntVar(&threads, "n", 400, "set threads")
	flag.StringVar(&export, "o", "all", "export to xlsx,txt, param 'no' to cancel")
	flag.StringVar(&fileName, "f", "result", "export file name")
	flag.BoolVar(&noPing, "p0", false, "skip host discovery")
	flag.BoolVar(&powerful, "p1", false, "powerful banner scan, use sparingly")
	flag.BoolVar(&debug, "debug", false, "real-time printing of scan")
	flag.Usage = rebuildFlag
	flag.Parse()
}

func (c *CliInfo) PrintCliInfo() {
	fmt.Printf("%+v", c)
}

func Version() {
	//Graffiti
	version := `
  __         .__        .__ 
_/  |______  |__|___.__.|__|
\   __\__  \ |  <   |  ||  |
 |  |  / __ \|  |\___  ||  |
 |__| (____  /__|/ ____||__|
           \/    \/         
  By. Whoopsunix	v1.0`
	fmt.Print(version)

	introduce := `
Supported Scanning Techniques:
ss: port scan only
sv: port scan and banner identify
sp: do no further than determining if host is online

`
	fmt.Print(introduce)
}

//rebuild flag command
func rebuildFlag() {
	flagSet := flag.CommandLine
	order := []string{"i", "p", "t", "n", "o", "f", "p0", "p1", "debug"}
	fmt.Printf("Usage of %s:\n", flagSet.Name())
	for _, name := range order {
		f := flagSet.Lookup(name)
		typeName, usage := flag.UnquoteUsage(f)
		fmt.Printf("  -%s %s\r\n", f.Name, typeName)
		// no print bool
		if f.Value.String() == "false" || f.Value.String() == "true" {
			fmt.Printf("\t%s\r\n", usage)
		} else {
			fmt.Printf("\t%s (default \"%s\")\r\n", usage, f.DefValue)
		}
	}
}
