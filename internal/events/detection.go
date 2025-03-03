package events

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ProtocolDetectionEvent struct {
	ProtocolName   string
	PacketMetaData gopacket.PacketMetadata
	PacketLayers   []gopacket.LayerType
}

func (e *ProtocolDetectionEvent) EventType() string {
	return string(ProtocolDetected)
}

type TcpPacketEvent struct {
	TCP            *layers.TCP
	PacketMetaData gopacket.PacketMetadata
}

func (e *TcpPacketEvent) EventType() string {
	return string(TCPPacketEvent)
}
