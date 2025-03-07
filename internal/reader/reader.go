package reader

import (
	"fmt"

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

func (pr *PCAPReader) ReadPackets() {}
func (pr *PCAPReader) GetFileInfo() {}
