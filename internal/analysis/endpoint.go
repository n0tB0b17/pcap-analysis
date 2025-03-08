package analysis

import (
	"fmt"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type EndpointStats struct {
	IP                  net.IP
	MAC                 net.HardwareAddr
	PacketSend          int
	PacketReceived      int
	ByteSend            int64
	ByteReceived        int64
	Protocol            map[string]int
	ConnectionInitiated int
	ConnectionReceived  int
	TopDestinations     map[string]int
	TopPorts            map[uint16]int
}

type EndpointAnalysis struct {
	endpoints   map[string]*EndpointStats
	ipToMAC     map[string]net.HardwareAddr
	connections map[string]bool
	mu          sync.Mutex
}

func NewEndpointAnalyzer() *EndpointAnalysis {
	return &EndpointAnalysis{
		endpoints:   make(map[string]*EndpointStats),
		ipToMAC:     make(map[string]net.HardwareAddr),
		connections: make(map[string]bool),
	}
}

func (ea *EndpointAnalysis) Analyze(packets []gopacket.Packet) {
	fmt.Printf("total number of packets to endpoint detection is: %d \n", len(packets))
	for _, packet := range packets {
		ea.analyzePacket(packet)
	}
}

func (ea *EndpointAnalysis) analyzePacket(packet gopacket.Packet) {
	// ethernet layer
	var SrcMAC, DestMac net.HardwareAddr
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		SrcMAC = eth.SrcMAC
		DestMac = eth.DstMAC
	}

	// ip layer
	var SrcIP, DestIP net.IP
	var ipProtocol string

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		addr, _ := ipv4Layer.(*layers.IPv4)
		SrcIP = addr.SrcIP
		DestIP = addr.DstIP
		ipProtocol = "IPv4"
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		addr, _ := ipv6Layer.(*layers.IPv6)
		SrcIP = addr.SrcIP
		DestIP = addr.DstIP
		ipProtocol = "IPv6"
	} else {
		fmt.Println("no endpoint analysis for given packet")
		return
	}

	// mapping ip to mac
	if SrcMAC != nil && SrcIP != nil {
		ea.mu.Lock()
		ea.ipToMAC[SrcIP.String()] = SrcMAC
		ea.mu.Unlock()
	}

	if DestMac != nil && DestIP != nil {
		ea.mu.Lock()
		ea.ipToMAC[DestIP.String()] = DestMac
		ea.mu.Unlock()
	}

	// transport layer
	var SrcPort, DestPort uint16
	var transportProtocol string
	var isSyn bool

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		SrcPort = uint16(tcp.SrcPort)
		DestPort = uint16(tcp.DstPort)
		transportProtocol = "TCP"
		isSyn = tcp.SYN && !tcp.ACK
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		SrcPort = uint16(udp.SrcPort)
		DestPort = uint16(udp.DstPort)
		transportProtocol = "UDP"
	} else {
		transportProtocol = "Other"
	}

	// application layer
	appProtocol := "Unknown"
	if packet.Layer(layers.LayerTypeDNS) != nil {
		appProtocol = "DNS"
	} else if packet.Layer(layers.LayerTypeTLS) != nil {
		appProtocol = "TLS"
	} else if transportProtocol == "TCP" {
		if DestPort == 80 {
			appProtocol = "HTTP"
		} else if DestPort == 443 {
			appProtocol = "HTTPS"
		} else if DestPort == 22 {
			appProtocol = "SSH"
		} else if DestPort == 21 {
			appProtocol = "FTP"
		} else if DestPort == 25 || DestPort == 587 {
			appProtocol = "SMTP"
		} else if DestPort == 110 {
			appProtocol = "POP3"
		} else if DestPort == 143 {
			appProtocol = "IMAP"
		}
	} else if transportProtocol == "UDP" {
		if DestPort == 53 {
			appProtocol = "DNS"
		} else if DestPort == 67 || DestPort == 68 {
			appProtocol = "DHCP"
		} else if DestPort == 123 {
			appProtocol = "NTP"
		} else if DestPort == 161 {
			appProtocol = "SNMP"
		}
	}

	fmt.Println(ipProtocol, SrcPort, isSyn)
	fmt.Printf("Application layer protocol is: %s \n", appProtocol)
}
