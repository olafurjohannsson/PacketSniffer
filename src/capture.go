package PacketSniffer

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

const (
	app_name = "PacketSniffer"
	version  = 0.1
	queue    = 100
)



// Start receiving http requests on an output channel
func (monitor *HttpMonitor) Receive() chan HttpRequest {

	if (monitor.requests == nil) {
		monitor.requests = make(chan HttpRequest, queue)
		// go listen..
		go monitor.listen()
	}



	// return channel to our requests
	return monitor.requests
}

// Init our monitor
func Start(device string) *HttpMonitor {
	// Create monitor
	return &HttpMonitor{
		TimeStamp: time.Now(),
		device:    device,
		requests: nil,
	}
}
// Start listen on a network interface
func (monitor *HttpMonitor) listen() {
	defer close(monitor.requests)
	
	handle, err := pcap.OpenLive(monitor.device, 1024, false, 30 * time.Second)

	if err != nil {
		fmt.Println(err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// Create our net parser
	parser := CreateParser()

	for packet := range packetSource.Packets() {
		if packet != nil {

			// if host is valid
			host := parser.GetHost(packet)

			if host != "" {
				// new httprequest
				req := HttpRequest{}
				req.TimeStamp = time.Now()

				// get host
				req.Host = host
				req.Url = host

				// get ips
				req.SrcIP, req.DstIP = parser.GetSrcDstIPs(packet)

				// get ports
				req.SrcPort, req.DstPort = parser.GetSrcDstPorts(packet)

				// put into channel
				monitor.requests <- req
			}
		}
	}
}

