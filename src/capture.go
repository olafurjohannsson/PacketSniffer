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

	if (monitor.Requests == nil) {
		monitor.Requests = make(chan HttpRequest, queue)
		// go listen..
		go monitor.listen()
	}



	// return channel to our requests
	return monitor.Requests
}

// Init our monitor
func Start(device string) *HttpMonitor {
	// Create monitor
	return &HttpMonitor{
		TimeStamp: time.Now(),
		Timeout: 30 * time.Second,
		Device:    device,
		Promiscous: false,
		SnapshotLength: 1024,
		Requests: nil,
	}
}
// Start listen on a network interface
func (monitor *HttpMonitor) listen() {
	defer close(monitor.Requests)
	
	handle, err := pcap.OpenLive(monitor.Device, monitor.SnapshotLength, monitor.Promiscous, monitor.Timeout)

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
				monitor.Requests <- req
			}
		}
	}
}

