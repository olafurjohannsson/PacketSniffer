package PacketSniffer

import "time"

type Monitor interface {
	Start() HttpMonitor
	Receive() chan HttpRequest
}

// The concrete http-monitor type
type HttpMonitor struct {
	Device    string
	Requests  chan HttpRequest
	TimeStamp time.Time
    Timeout time.Duration
    SnapshotLength int32
    Promiscous bool
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

type HttpRequests []HttpRequest