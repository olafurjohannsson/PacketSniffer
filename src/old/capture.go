package Packets

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle
)

// HTTP request
type HTTPRequestEntity struct {
	Host string
	IP   string
	Port string
}

type PacketCapture struct {
}

// Listen ...
func Monitor(device string) <-chan HTTPRequestEntity {

	packets := make(chan HTTPRequestEntity)

	// Open handle to network device
	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)

	if err != nil {
		fmt.Println(err)
	}

	// Cleanup
	//defer handle.Close()

	// Source of our packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		// Stream of packets
		for packet := range packetSource.Packets() {

			// create our HTTP package
			http := HTTPRequestEntity{}

			// Get IPV4 packet and extract destination IP
			ipv4 := packet.Layer(layers.LayerTypeIPv4)
			if ipv4 != nil {
				f := ipv4.(*layers.IPv4)

				http.IP = f.DstIP.String()
			}

			// Get TCP packet and extract destination Port
			tcp := packet.Layer(layers.LayerTypeTCP)
			if tcp != nil {
				t := tcp.(*layers.TCP)

				http.Port = t.DstPort.String()
			}

			// check app package
			app := packet.ApplicationLayer()
			if app != nil {

				// get payload string
				payload := string(app.Payload())

				// If HTTP string
				if strings.Contains(payload, "HTTP") {

					// Contains Host header value
					r := regexp.MustCompile("Host: [A-Za-z].*")

					// Found string in our payload
					if r.MatchString(payload) {
						// Get host: value
						host := strings.Split(r.FindString(payload), ":")

						// Only extract value
						http.Host = strings.TrimSpace(host[1])
						fmt.Printf("Found packet host: %s\n", http.Host)
						packets <- http

					}
				}
			}
		}
	}()

	return packets
}
