package reader

import (
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type PCAPReader struct {
	filePath string
	handle   *pcap.Handle
}

func NewPCAPReader(path string) *PCAPReader {
	return &PCAPReader{
		filePath: path,
	}
}

func (pr *PCAPReader) Open() error {
	var err error

	pr.handle, err = pcap.OpenOffline(pr.filePath)
	if err != nil {
		return fmt.Errorf("error while opening pcap file named: %s | error: %v \n", pr.filePath, err)
	}

	return nil
}

func (pr *PCAPReader) Close() {
	if pr.handle != nil {
		pr.handle.Close()
	}
}

func (pr *PCAPReader) ReadPackets() ([]gopacket.Packet, error) {
	if pr.handle == nil {
		return nil, fmt.Errorf("no handle found for pcap file: %s \n", pr.filePath)
	}

	var packets []gopacket.Packet
	packetSource := gopacket.NewPacketSource(pr.handle, pr.handle.LinkType())

	for pck := range packetSource.Packets() {
		packets = append(packets, pck)
	}

	return packets, nil
}

type PCAPFileInfo struct {
	FileName    string
	FileSize    int64
	ModTime     time.Time
	IsDirectory bool
	PacketCount int
	TimeRange   PCAPDuration
}

type PCAPDuration struct {
	firstTime time.Time
	lastTime  time.Time
	duration  string
}

func (pr *PCAPReader) GetFileInfo() (PCAPFileInfo, error) {
	fileInfo, err := os.Stat(pr.filePath)
	if err != nil {
		fmt.Println("error while running GetFileInfo() function")
		return PCAPFileInfo{}, fmt.Errorf("error while looking for pcap file information, file path: %s | err: %v", pr.filePath, err)
	}

	info := PCAPFileInfo{
		FileName:    fileInfo.Name(),
		FileSize:    fileInfo.Size(),
		ModTime:     fileInfo.ModTime(),
		IsDirectory: fileInfo.IsDir(),
	}

	if pr.handle != nil {
		packet, err := pr.ReadPackets()
		if err != nil {
			return info, err
		}

		var firstTime, lastTime time.Time
		if len(packet) > 0 {
			firstTime = packet[0].Metadata().Timestamp
			lastTime = packet[len(packet)-1].Metadata().Timestamp
		}

		info.PacketCount = len(packet)
		info.TimeRange.firstTime = firstTime
		info.TimeRange.lastTime = lastTime
		info.TimeRange.duration = lastTime.Sub(firstTime).String()
	}

	fmt.Println(info)
	return info, nil
}
