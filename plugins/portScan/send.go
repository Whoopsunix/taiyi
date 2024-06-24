package portScan

import (
	"errors"
	"fmt"
	"net"
	"time"
)

func NewSend(protocol string, data []byte, ip string, port uint) (error, []byte) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout(protocol, addr, 6*time.Second)
	if err != nil {
		return errors.New("connect err"), nil
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	if _, err := conn.Write(data); err != nil {
		return errors.New("write err"), nil
	}
	receive := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(6 * time.Second)); err != nil {
		return errors.New("setRead err"), nil
	}
	length, err := conn.Read(receive)
	if err != nil {
		//fmt.Println("3 err")
		//fmt.Println(err)
		return errors.New("read err"), receive[:length]
	}
	if length == 0 {
		return errors.New("empty"), receive[:length]
	}

	return nil, receive[:length]
}

func Send(protocol string, data []byte, ip string, port uint) (bool, string) {
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := net.DialTimeout(protocol, addr, 1*time.Second)
	if err != nil {
		return false, "1 err"
	}
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	if _, err := conn.Write(data); err != nil {
		return false, "2 err"
	}
	receive := make([]byte, 2048)
	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return false, ""
	}
	length, err := conn.Read(receive)
	if err != nil {
		//fmt.Println("3 err")
		//fmt.Println(err)
		return false, "3 err"
	}
	if length == 0 {
		return false, "empty"
	}

	//fmt.Println(receive[:length])
	//fmt.Println(hex.EncodeToString(receive[:length]))
	return true, string(receive[:length])

}
