package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

var fwdDestination = flag.String("destination", "", "Destination of the forwarded requests.")
var fwdPerc = flag.Float64("percentage", 100, "Must be between 0 and 100.")
var fwdBy = flag.String("percentage-by", "", "Can be empty. Otherwise, valid values are: header, remoteaddr.")
var fwdHeader = flag.String("percentage-by-header", "", "If percentage-by is header, then specify the header here.")
var reqPort = flag.Int("filter-request-port", 80, "Must be between 0 and 65535.")
var keepHostHeader = flag.Bool("keep-host-header", false, "Keep Host header from original request.")

func main() {
	flag.Parse()

	// Define the network interface to capture packets on
	ifaceName := "vxlan0" // Change to the appropriate network interface

	// Open a packet capture handle on the specified network interface
	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("Error opening capture:", err)
	}
	defer handle.Close()

	// Set a BPF filter to capture only TCP traffic on port 80 (HTTP)
	filter := fmt.Sprintf("%s%d", "tcp and dst port ", *reqPort)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal("Error setting BPF filter:", err)
	}

	// Start packet capture
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	fmt.Printf("Start Capturing packets")

	for packet := range packetSource.Packets() {
		// Process received packets
		processPacket(packet)
	}

	fmt.Printf("done ")
}

func forwardRequest(req *http.Request, reqSourceIP string, reqDestionationPort string, body []byte) {

	fmt.Println("fwdDestination:", *fwdDestination)

	url := fmt.Sprintf("%s%s", string(*fwdDestination), req.RequestURI)

	// create a new HTTP request
	forwardReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))
	if err != nil {
		return
	}

	// add headers to the new HTTP request
	for header, values := range req.Header {
		for _, value := range values {
			forwardReq.Header.Add(header, value)
		}
	}

	//log.Println(forwardReq)

	// Append to X-Forwarded-For the IP of the client or the IP of the latest proxy (if any proxies are in between)
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
	forwardReq.Header.Add("X-Forwarded-For", reqSourceIP)
	// The three following headers should contain 1 value only, i.e. the outermost port, protocol, and host
	// https://tools.ietf.org/html/rfc7239#section-5.4
	if forwardReq.Header.Get("X-Forwarded-Port") == "" {
		forwardReq.Header.Set("X-Forwarded-Port", reqDestionationPort)
	}
	if forwardReq.Header.Get("X-Forwarded-Proto") == "" {
		forwardReq.Header.Set("X-Forwarded-Proto", "http")
	}
	if forwardReq.Header.Get("X-Forwarded-Host") == "" {
		forwardReq.Header.Set("X-Forwarded-Host", req.Host)
	}

	//if keepHostHeader {
	//forwardReq.Host = req.Host
	//}

	fmt.Printf("Destination: %s\n", url)

	// var headerString strings.Builder

	// // Print request headers
	// fmt.Println("Request Headers:")
	// for key, values := range forwardReq.Header {
	// 	for _, value := range values {
	// 		fmt.Printf("%s: %s\n", key, value)
	// 		headerString.WriteString(fmt.Sprintf("%s: %s, ", key, value))

	// 	}
	// }
	// fmt.Println(string(body))

	// Execute the new HTTP request
	httpClient := &http.Client{}
	resp, rErr := httpClient.Do(forwardReq)
	if rErr != nil {
		// log.Println("Forward request error", ":", err)
		return
	}

	defer resp.Body.Close()

	body2, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(body2))

	// Your input text
	inputText := `{"Status":null,"Order":null}`

	if strings.Compare(inputText, string(body2)) == 0 {
		fmt.Println("Bodys")
		fmt.Println(string(body))
	}
}

func processPacket(packet gopacket.Packet) error {
	appLayer := packet.ApplicationLayer()
	networkLayer := packet.NetworkLayer()
	if appLayer != nil {
		payload := appLayer.Payload()
		// Check if it's an HTTP request (typically starts with "GET" or "POST")
		if strings.HasPrefix(string(payload), "POST") || strings.HasPrefix(string(payload), "PUT") {
			// Process the HTTP request
			//fmt.Printf("Received HTTP request:\n%s\n", payload)

			payloadStr := string(payload)

			payloadReader := bufio.NewReader(strings.NewReader(payloadStr))

			// Create an HTTP request based on the payload
			req, err := http.ReadRequest(payloadReader)
			if err == io.EOF {
				// We must read until we see an EOF... very important!
				return nil
			} else if err != nil {
				log.Println("Error reading stream ", err)
				return err
			} else {
				reqSourceIP := networkLayer.NetworkFlow().Src().String()
				reqDestionationPort := networkLayer.NetworkFlow().Dst().String()
				body, bErr := ioutil.ReadAll(req.Body)
				if bErr != nil {
				}
				req.Body.Close()
				requestUri := strings.ToLower(req.RequestURI)

				fmt.Println("RequestURI:", requestUri)

				if strings.Contains(requestUri, "v5/saveorder") || strings.Contains(requestUri, "v5/updateorder") {
					go forwardRequest(req, reqSourceIP, reqDestionationPort, body)
				}
			}

		}
	} else {

	}
	return nil
}
