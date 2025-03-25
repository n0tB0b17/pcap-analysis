package analysis

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ProtocolStats struct {
	Count       int
	TotalBytes  int64
	MinSize     int
	MaxSize     int
	PacketIDs   []int
	Description string
	MetaStat    *ProtocolMetaStats
}

type ProtocolMetaStats struct {
	SrcIP        string
	SrcPort      int
	DestIP       string
	DestPort     int
	SrcMAC       string
	DestMAC      string
	ICMPType     uint8
	ICMPCode     uint8
	ProtocolType string
	Seq          int
	Ack          int
}

type ProtocolAnalyzer struct {
	PacketCount           int
	LinkLayerStats        map[string]*ProtocolStats
	NetworkLayerStats     map[string]*ProtocolStats
	TransportLayerStats   map[string]*ProtocolStats
	ApplicationLayerStats map[string]*ProtocolStats
	mu                    sync.Mutex
}

func NewProtocolAnalyzer() *ProtocolAnalyzer {
	return &ProtocolAnalyzer{
		LinkLayerStats:        make(map[string]*ProtocolStats),
		NetworkLayerStats:     make(map[string]*ProtocolStats),
		TransportLayerStats:   make(map[string]*ProtocolStats),
		ApplicationLayerStats: make(map[string]*ProtocolStats),
	}
}

func (pa *ProtocolAnalyzer) Analyze(packets []gopacket.Packet) {
	pa.PacketCount = len(packets)
	var wg sync.WaitGroup

	for i, packet := range packets {
		wg.Add(1)
		go func(packet gopacket.Packet, i int) {
			defer wg.Done()
			pa.analyzePacket(packet, i)
		}(packet, i)
	}

	wg.Wait()
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

func (pa *ProtocolAnalyzer) GetJSONResult() ([]byte, error) {
	resp := pa.GetResult()

	return json.MarshalIndent(resp, "", " ")
}

func (pa *ProtocolAnalyzer) analyzePacket(packet gopacket.Packet, identifier int) {
	if linkLayer := packet.LinkLayer(); linkLayer != nil {
		pa.updateProtocolStats(
			pa.LinkLayerStats,
			linkLayer.LayerType().String(),
			packet.Metadata().Length, // in bytes
			identifier,
			getMetaData(linkLayer),
		)

	}

	if networkLayer := packet.NetworkLayer(); networkLayer != nil {
		pa.updateProtocolStats(
			pa.NetworkLayerStats,
			networkLayer.LayerType().String(),
			packet.Metadata().Length,
			identifier,
			getMetaData(networkLayer),
		)
	}

	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		pa.updateProtocolStats(
			pa.TransportLayerStats,
			transportLayer.LayerType().String(),
			packet.Metadata().Length,
			identifier,
			getMetaData(transportLayer),
		)
	}

	if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {
		appProtocol := applicationLayer.LayerType().String()

		if appProtocol == "" {
			appProtocol = "unknown"
		}

		pa.updateProtocolStats(
			pa.ApplicationLayerStats,
			appProtocol,
			len(applicationLayer.Payload()),
			identifier,
			nil,
		)
	}
}

func (pa *ProtocolAnalyzer) updateProtocolStats(
	statsMap map[string]*ProtocolStats,
	protocol string,
	size int,
	packetID int,
	metadata *ProtocolMetaStats,
) {
	pa.mu.Lock()
	defer pa.mu.Unlock()

	stats := pa.getOrCreateStats(statsMap, protocol, size)
	pa.updateStats(stats, size, packetID)

	if stats.MetaStat == nil && metadata != nil {
		stats.MetaStat = metadata
	}
}

func (pa *ProtocolAnalyzer) getOrCreateStats(
	statsMap map[string]*ProtocolStats,
	protocol string,
	size int,

) *ProtocolStats {
	stats, doesExist := statsMap[protocol]
	if !doesExist {
		stats = &ProtocolStats{
			MinSize: size,
			MaxSize: size,
		}

		statsMap[protocol] = stats
	}

	return stats
}

func (pa *ProtocolAnalyzer) updateStats(stats *ProtocolStats, size, packetID int) {
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

func formatProtocolStats(stats map[string]*ProtocolStats) map[string]interface{} {
	resp := make(map[string]interface{})

	for protocol, stat := range stats {
		protocolData := map[string]interface{}{
			"count":      stat.Count,
			"totalBytes": stat.TotalBytes,
			"minSize":    stat.MinSize,
			"maxSize":    stat.MaxSize,
			"avgSize":    float64(stat.TotalBytes) / float64(stat.Count),
			// "packetIDs":   stat.PacketIDs,
			"description": stat.Description,
		}

		if stat.MetaStat != nil {
			protocolData["metadata"] = map[string]interface{}{
				"srcIP":        stat.MetaStat.SrcIP,
				"srcPort":      stat.MetaStat.SrcPort,
				"destIP":       stat.MetaStat.DestIP,
				"destPort":     stat.MetaStat.DestPort,
				"srcMAC":       stat.MetaStat.SrcMAC,
				"destMAC":      stat.MetaStat.DestMAC,
				"icmpType":     stat.MetaStat.ICMPType,
				"icmpCode":     stat.MetaStat.ICMPCode,
				"protocolType": stat.MetaStat.ProtocolType,
				"sequence":     stat.MetaStat.Seq,
				"acknowledge":  stat.MetaStat.Ack,
			}
		}
		resp[protocol] = protocolData
	}

	return resp
}

func getMetaData(layer gopacket.Layer) *ProtocolMetaStats {
	metaData := &ProtocolMetaStats{}
	switch layer.LayerType() {
	case layers.LayerTypeEthernet:
		eth, _ := layer.(*layers.Ethernet)

		metaData.SrcMAC = eth.SrcMAC.String()
		metaData.DestMAC = eth.DstMAC.String()
		return metaData

	case layers.LayerTypeIPv4:
		ip, _ := layer.(*layers.IPv4)

		metaData.SrcIP = ip.SrcIP.String()
		metaData.DestIP = ip.DstIP.String()
		return metaData

	case layers.LayerTypeIPv6:
		ip, _ := layer.(*layers.IPv6)
		metaData.SrcIP = ip.SrcIP.String()
		metaData.DestIP = ip.DstIP.String()
		return metaData

	case layers.LayerTypeTCP:
		tcp, _ := layer.(*layers.TCP)

		metaData.SrcPort = int(tcp.SrcPort)
		metaData.DestPort = int(tcp.DstPort)
		return metaData

	case layers.LayerTypeUDP:
		udp, _ := layer.(*layers.UDP)
		metaData.SrcPort = int(udp.SrcPort)
		metaData.DestPort = int(udp.DstPort)
		return metaData

	case layers.LayerTypeICMPv4:
		icmp, _ := layer.(*layers.ICMPv4)
		metaData.ICMPType = icmp.TypeCode.Type()
		metaData.ICMPCode = icmp.TypeCode.Code()
		return metaData

	case layers.LayerTypeICMPv6:
		icmp, _ := layer.(*layers.ICMPv6)
		metaData.ICMPType = icmp.TypeCode.Type()
		metaData.ICMPCode = icmp.TypeCode.Code()
		return metaData

	default:
		return metaData
	}
}

func getLayerDescription(layer gopacket.Layer) string {
	switch layer.LayerType() {
	case layers.LayerTypeEthernet:
		eth, _ := layer.(*layers.Ethernet)
		return fmt.Sprintf("Ethernet frame: SrcMAC |> %v --> DstMAC |> %v \n", eth.SrcMAC, eth.DstMAC)

	case layers.LayerTypeIPv4:
		ip, _ := layer.(*layers.IPv4)
		return fmt.Sprintf("IPv4 packet: SrcIP |> %v --> DstIP |> %v \n", ip.SrcIP, ip.DstIP)

	case layers.LayerTypeIPv6:
		ip, _ := layer.(*layers.IPv6)
		return fmt.Sprintf("IPv6 packet: SrcIP |> %v --> DstIP |> %v \n", ip.SrcIP, ip.DstIP)

	case layers.LayerTypeTCP:
		tcp, _ := layer.(*layers.TCP)
		return fmt.Sprintf("TCP segment: SrcPort |> %v --> DstPort |> %v || seq: %v | ack: %v \n", tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack)

	case layers.LayerTypeUDP:
		udp, _ := layer.(*layers.UDP)
		return fmt.Sprintf("UDP datagram: SrcPort |> %v --> DstPort |> %v \n", udp.SrcPort, udp.DstPort)

	case layers.LayerTypeICMPv4:
		icmp, _ := layer.(*layers.ICMPv4)
		return fmt.Sprintf("ICMPv4 message: Type |> %v || Code |> %v \n", icmp.TypeCode.Type(), icmp.TypeCode.Code())

	case layers.LayerTypeICMPv6:
		icmp, _ := layer.(*layers.ICMPv6)
		return fmt.Sprintf("ICMPv6 message: Type |> %v || Code |> %v \n", icmp.TypeCode.Type(), icmp.TypeCode.Code())

	default:
		return fmt.Sprintf("%v layer \n", layer.LayerType())
	}
}
