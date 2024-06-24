package common

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/tidwall/gjson"
	"os"
	"strconv"
	"strings"
)


// GetLinesFromFile 文件中逐行读取
func GetLinesFromFile(filePath string) (error, []string) {
	errMsg := errors.New(fmt.Sprintf("file open failed: %s", filePath))
	path, err := os.Stat(filePath)
	if err != nil || path.IsDir() {
		return errMsg, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return errMsg, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var lines []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}
	return nil, lines
}

// GetPorts gjson.Result-> ports
func GetPorts(ports gjson.Result) []int {
	ports_list := []int{}
	ports.ForEach(func(key, port gjson.Result) bool {
		if strings.Contains(port.String(), "-") {
			//fmt.Println(port)
			parts := strings.Split(port.String(), "-")
			p1, _ := strconv.Atoi(parts[0])
			p2, _ := strconv.Atoi(parts[1])
			for i := p1; i <= p2; i++ {
				ports_list = append(ports_list, i)
			}
		} else {
			t, _ := strconv.Atoi(port.Str)
			ports_list = append(ports_list, t)
		}
		return true
	})
	return ports_list
}
