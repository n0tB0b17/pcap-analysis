package main

import (
	"fmt"
	"log"

	"github.com/bob17/capp/internal/analysis"
	"github.com/bob17/capp/internal/config"
	"github.com/bob17/capp/internal/reader"
)

func main() {
	cfgPath := "internal/config/config.yaml"
	defCfg := config.GetDefaultConfig()
	yamlDecoder := &config.YAMLConfigLoader{}

	err := yamlDecoder.LoadConfig(cfgPath, defCfg)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	for idx, pcap := range defCfg.PcapFiles {
		fmt.Printf("Path to pcap file: %s \n", pcap)

		reader := reader.NewPCAPReader(defCfg.PcapFiles[idx])
		err := reader.Open()
		if err != nil {
			log.Fatalf("unable to open pcap file: %v", err)
		}
		defer reader.Close()

		pck, err := reader.ReadPackets()
		if err != nil {
			log.Fatalf("unable to read packets: %v", err)
		}

		analyzer := analysis.NewProtocolAnalyzer()
		analyzer.Analyze(pck)
		resp := analyzer.GetResult()

		for protocol, stats := range resp {
			fmt.Printf("[%s] >> %v \n", protocol, stats)
		}
	}
}
