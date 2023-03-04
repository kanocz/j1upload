package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path"
	"strings"
	"time"
)

var (
	discoverTimeout = flag.Duration("discover.timeout", time.Second*5, "printer discovery timeout")
)

func getPrinter() *net.UDPAddr {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		log.Println("unable to listen UDP:", err)
		return nil
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(*discoverTimeout))

	broadcast := &net.UDPAddr{IP: []byte{255, 255, 255, 255}, Port: 20054}
	_, err = conn.WriteToUDP([]byte("discover"), broadcast)
	if err != nil {
		log.Println("unable to send UDP broadcast:", err)
		return nil
	}

	buf := make([]byte, 1500) // 1500 is default MTU on most systems
	for {

		l, addr, err := conn.ReadFromUDP(buf)
		if err != nil || l < 2 {
			log.Println("unable discover printer:", err)
			return nil
		}

		parts := strings.Split(string(buf[:l]), "|")
		if len(parts) != 3 {
			log.Println("Unknown printer responce: ", string(buf[:l]))
			continue
		}

		if parts[1] != "model:Snapmaker J1" || parts[2] != "SACP:1" {
			log.Println("Not J1 printer found: ", string(buf[:l]), " at ", addr.IP)
			continue
		}

		log.Println("Printer found: ", parts[0])
		return addr
	}
}

func main() {

	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprint(os.Stderr, "Use with gcode filename\n\n")
		flag.Usage()
		return
	}
	filename := args[0]

	uploadFilename := filename
	if envFilename := os.Getenv("SLIC3R_PP_OUTPUT_NAME"); envFilename != "" {
		uploadFilename = envFilename
	}
	uploadFilename = path.Base(uploadFilename)

	log.Println("Using filename: ", uploadFilename)

	addr := getPrinter()
	if addr == nil {
		os.Exit(-1)
	}

	conn := SACP_connect(addr.IP.String(), time.Second*5)
	if conn == nil {
		os.Exit(-2)
	}
	defer conn.Close()

	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatalln("Error reading \""+filename+"\": ", err)
	}

	err = SACP_start_upload(conn, uploadFilename, data, time.Second*10)
	if err != nil {
		log.Fatalln("Error writing \"job\": ", err)
	}

}
