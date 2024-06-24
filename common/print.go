package common

import (
	"log"
)

/*
自定义输出类
[-] 实时数据的输出
[!] 警告
[+] 阶段性提示
*/

const (
	Flags = log.Ldate | log.Ltime
)

func init() {
	log.SetFlags(Flags)
}

/*
control by -debug
*/

// Log Println
func (c *CliInfo) Log(values ...interface{}) {
	if !c.Debug {
		return
	}
	log.Printf("[-] %s [-]\n", values)
}

// LogSpecial Special Println
func (c *CliInfo) LogSpecial(values ...interface{}) {
	if !c.Debug {
		return
	}
	log.Printf("[*] %s [*]\n", values)
}

// Warn Println
func (c *CliInfo)Warn(values ...interface{}) {
	if !c.Debug {
		return
	}
	log.Printf("[!] %v [!]\n", values)
}

/*
no control by -debug
*/

// Info Println
func Info(values ...interface{}) {
	log.Printf("[+] %s [+]\n", values)
}

// InfoSpecial Println
func InfoSpecial(values ...interface{}) {
	log.Printf("[*] %s [*]\n", values)
}

// Warn Println
func Warn(values ...interface{}) {
	log.Printf("[!] %s [!]\n", values)
}
