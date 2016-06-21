package PacketSniffer

import "time"

type Monitor interface {
	Start() HttpMonitor
	Receive() chan HttpRequest
}

// The concrete http-monitor type
type HttpMonitor struct {
	device    string
	requests  chan HttpRequest
	TimeStamp time.Time
}

// An instance of a HTTP request
type HttpRequest struct {
	Url  string
	Host string

	DstPort int
	SrcPort int

	DstIP string
	SrcIP string

	TimeStamp time.Time
}