package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

var (
	discoverTimeout = flag.Duration("discover.timeout", time.Second*5, "printer discovery timeout")
)

func getPrinter() (string, *net.UDPAddr) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		fmt.Println("unable to listen UDP:", err)
		return "", nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(*discoverTimeout))

	broadcast := &net.UDPAddr{IP: []byte{255, 255, 255, 255}, Port: 20054}
	_, err = conn.WriteToUDP([]byte("discover"), broadcast)
	if err != nil {
		fmt.Println("unable to send UDP broadcast:", err)
		return "", nil
	}

	buf := make([]byte, 1500) // 1500 is default MTU on most systems
	l, addr, err := conn.ReadFromUDP(buf)
	if err != nil || l < 2 {
		fmt.Println("unable discover printer:", err)
		return "", nil
	}

	return string(buf[:l]), addr
}

func SACP_connect(ip string) net.Conn {
	conn, err := net.Dial("tcp4", ip+":8888")
	if err != nil {
		log.Printf("Error connecting to %s: %v", ip, err)
		return nil
	}

	return conn
}

func main() {
	msg, addr := getPrinter()
	fmt.Println("Found ", msg, " on ", addr.IP)
}
