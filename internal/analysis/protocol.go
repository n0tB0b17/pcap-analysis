package analysis

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ProtocolAnalyzer struct {
	PacketCount           int
	LinkLayerStats        map[string]*Stats
	NetworkLayerStats     map[string]*Stats
	TransportLayerStats   map[string]*Stats
	ApplicationLayerStats map[string]*Stats
	mu                    sync.Mutex
}

func NewProtocolAnalyzer() *ProtocolAnalyzer {
	return &ProtocolAnalyzer{
		LinkLayerStats:        make(map[string]*Stats),
		NetworkLayerStats:     make(map[string]*Stats),
		TransportLayerStats:   make(map[string]*Stats),
		ApplicationLayerStats: make(map[string]*Stats),
	}
}

func (pa *ProtocolAnalyzer) Analyze(packets []gopacket.Packet) {
	pa.PacketCount = len(packets)

	for i, packet := range packets {
		pa.analyzePacket(packet, i)
	}
}

func (pa *ProtocolAnalyzer) analyzePacket(packet gopacket.Packet, identifier int) {
	if linkLayer := packet.LinkLayer(); linkLayer != nil {
		pa.updateProtocolStats(
			pa.LinkLayerStats,
			linkLayer.LayerType().String(),
			packet.Metadata().Length, // in bytes
			identifier,
			getLayerDescription(linkLayer),
		)

	}

	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		pa.updateProtocolStats(
			pa.NetworkLayerStats,
			networkLayer.LayerType().String(),
			packet.Metadata().Length,
			identifier,
			getLayerDescription(networkLayer),
		)
	}

	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		pa.updateProtocolStats(
			pa.TransportLayerStats,
			transportLayer.LayerType().String(),
			packet.Metadata().Length,
			identifier,
			getLayerDescription(transportLayer),
		)
	}

	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		appProtocol := ""

		if packet.Layer(layers.LayerTypeDNS) != nil {
			appProtocol = "DNS"
		} else if packet.Layer(layers.LayerTypeTLS) != nil {
			appProtocol = "TLS"
		} else if packet.Layer(layers.LayerTypeDHCPv4) != nil {
			appProtocol = "DHCPv4"
		} else if packet.Layer(layers.LayerTypeSIP) != nil {
			appProtocol = "SIP"
		} else if packet.Layer(layers.LayerTypeNTP) != nil {
			appProtocol = "NTP"
		}

		pa.updateProtocolStats(
			pa.ApplicationLayerStats,
			appProtocol,
			len(applicationLayer.Payload()),
			identifier,
			"Application data",
		)
	}
}

func (pa *ProtocolAnalyzer) updateProtocolStats(
	statsMap map[string]*Stats,
	protocol string,
	size int,
	packetID int,
	description string,
) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	stats, doesExist := statsMap[protocol]
	if !doesExist {
		stats = &Stats{
			MinSize:     size,
			MaxSize:     size,
			Description: description,
		}

		statsMap[protocol] = stats
	}

	stats.Count++
	stats.TotalBytes += int64(size)
	stats.PacketIDs = append(stats.PacketIDs, packetID)

	if size < stats.MinSize {
		stats.MinSize = size
	}

	if size > stats.MaxSize {
		stats.MaxSize = size
	}
}

func (pa *ProtocolAnalyzer) GetResult() map[string]interface{} {
	resp := map[string]interface{}{
		"totalPacket":      pa.PacketCount,
		"linkLayer":        formatProtocolStats(pa.LinkLayerStats),
		"networkLayer":     formatProtocolStats(pa.NetworkLayerStats),
		"transportLayer":   formatProtocolStats(pa.TransportLayerStats),
		"applicationLayer": formatProtocolStats(pa.ApplicationLayerStats),
	}

	return resp
}

func formatProtocolStats(stats map[string]*Stats) map[string]interface{} {
	resp := make(map[string]interface{})

	for protocol, stat := range stats {
		resp[protocol] = map[string]interface{}{
			"count":       stat.Count,
			"totalBytes":  stat.TotalBytes,
			"minSize":     stat.MinSize,
			"maxSize":     stat.MaxSize,
			"avgSize":     float64(stat.TotalBytes) / float64(stat.Count),
			"packetIDs":   stat.PacketIDs,
			"description": stat.Description,
		}
	}

	return resp
}

func getLayerDescription(layer gopacket.Layer) string {
	switch layer.LayerType() {
	case layers.LayerTypeEthernet:
		eth, _ := layer.(*layers.Ethernet)
		return fmt.Sprintf("Ethernet frame: SrcMAC |> %v --> DstMAC |> %v", eth.SrcMAC, eth.DstMAC)
	case layers.LayerTypeIPv4:
		ip, _ := layer.(*layers.IPv4)
		return fmt.Sprintf("IPv4 packet: SrcIP |> %v --> DstIP |> %v", ip.SrcIP, ip.DstIP)
	case layers.LayerTypeIPv6:
		ip, _ := layer.(*layers.IPv6)
		return fmt.Sprintf("IPv6 packet: SrcIP |> %v --> DstIP |> %v", ip.SrcIP, ip.DstIP)
	case layers.LayerTypeTCP:
		tcp, _ := layer.(*layers.TCP)
		return fmt.Sprintf("TCP segment: SrcPort |> %v --> DstPort |> %v || seq: %v | ack: %v", tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack)
	case layers.LayerTypeUDP:
		udp, _ := layer.(*layers.UDP)
		return fmt.Sprintf("UDP datagram: SrcPort |> %v --> DstPort |> %v", udp.SrcPort, udp.DstPort)
	case layers.LayerTypeICMPv4:
		return "ICMPv4 message"
	case layers.LayerTypeICMPv6:
		return "ICMPv6 message"
	default:
		return fmt.Sprintf("%v layer", layer.LayerType())
	}
}
