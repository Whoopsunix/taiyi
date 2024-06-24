package common

import (
	"bufio"
	"fmt"
	"github.com/xuri/excelize/v2"
	"os"
	"strconv"
)

type addr struct {
	ip   string
	port uint
}

type PortInfo struct {
	Ip   string
	Port uint
	// matchInfo
	Pattern string
	Name    string
	// versionInfo
	VendorProductName string
	OperatingSystem   string
	Info              string
	Version           string
}

func Export2xlsx(filename string, portInfoList []*PortInfo) error {
	f := excelize.NewFile()
	// Create a new sheet.
	sheetName := "result"
	index := f.NewSheet(sheetName)
	// Set column name.
	categories := map[string]string{
		"A1": "Ip", "B1": "Port", "C1": "Pattern", "D1": "Name", "E1": "VendorProductName"}
	for k, v := range categories {
		f.SetCellValue(sheetName, k, v)
	}
	// Set value of a cell.
	for k, portInfo := range portInfoList {
		f.SetSheetRow(sheetName, fmt.Sprint("A", k+2), &[]string{portInfo.Ip, strconv.Itoa(int(portInfo.Port)),
			portInfo.Pattern, portInfo.Name, portInfo.VendorProductName})
	}
	// Set active sheet of the workbook.
	f.SetActiveSheet(index)
	// Save spreadsheet by the given path.
	if err := f.SaveAs(filename + ".xlsx"); err != nil {
		return err
	}
	return nil
}

func Export2txt(filename string, portInfoList []*PortInfo) error {
	filePath := filename + ".txt"
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	//及时关闭file句柄
	defer file.Close()
	//写入文件时，使用带缓存的 *Writer
	write := bufio.NewWriter(file)
	for _, portInfo := range portInfoList {
		//fmt.Printf("%+v\n", portInfo)
		write.WriteString(fmt.Sprintf("%+v\r\n", portInfo))
	}
	//Flush将缓存的文件真正写入到文件中
	write.Flush()
	return nil
}
