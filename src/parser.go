package PacketSniffer

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
   Public interface of our net/http parser
*/
type Parser struct{}

func CreateParser() Parser {
	return Parser{}
}

// returns (srcIP, dstIP)
func (parser *Parser) GetSrcDstIPs(packet gopacket.Packet) (string, string) {
	// get IPV4
	ipv4Packet := parseIPv4(packet)
	if ipv4Packet != nil {
		dstIP := ipv4Packet.DstIP.String()
		srcIP := ipv4Packet.SrcIP.String()
		return srcIP, dstIP
	}
	return "", ""
}

// returns (srcPort, dstPort)
func (parser *Parser) GetSrcDstPorts(packet gopacket.Packet) (int, int) {
	tcpPacket := parseTCPPacket(packet)
	if tcpPacket != nil {
		dstPort, _ := strconv.Atoi(tcpPacket.DstPort.String())
		srcPort, _ := strconv.Atoi(tcpPacket.SrcPort.String())
		return srcPort, dstPort
	}
	return 0, 0
}

func (parser *Parser) GetHost(packet gopacket.Packet) string {
	return parseAppLayer(packet)
}

/* private interface */
func parseIPv6(packet gopacket.Packet) *layers.IPv6 {
	ipv6 := packet.Layer(layers.LayerTypeIPv6)
	if ipv6 != nil {
		ipv6Packet := ipv6.(*layers.IPv6)
		return ipv6Packet
	}
	return nil
}

func parseIPv4(packet gopacket.Packet) *layers.IPv4 {
	ipv4 := packet.Layer(layers.LayerTypeIPv4)
	if ipv4 != nil {
		ipv4Packet := ipv4.(*layers.IPv4)
		return ipv4Packet
	}
	return nil
}

func parseTCPPacket(packet gopacket.Packet) *layers.TCP {
	tcp := packet.Layer(layers.LayerTypeTCP)
	if tcp != nil {
		tcpPacket := tcp.(*layers.TCP)
		return tcpPacket
	}
	return nil
}

func parseAppLayer(packet gopacket.Packet) string {
	app := packet.ApplicationLayer()
	if app != nil {
		payload := string(app.Payload())

		if strings.Contains(payload, "HTTP") {

			regex := regexp.MustCompile("Host: [A-Za-z].*")

			if regex.MatchString(payload) {
				host := strings.Split(regex.FindString(payload), ":")
				return strings.TrimSpace(host[1])
			}
		}
	}
	return ""
}

func parseUDPPacket(packet gopacket.Packet) *layers.UDP {
	udp := packet.Layer(layers.LayerTypeUDP)
	if udp != nil {
		udpPacket := udp.(*layers.UDP)
		return udpPacket
	}
	return nil
}
