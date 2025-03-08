package analysis

import (
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
			packet.Metadata().Length,
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

}

func (pa *ProtocolAnalyzer) GetResult() {}

func getLayerDescription(layer gopacket.Layer) string {
	return layer.LayerType().String()
}
