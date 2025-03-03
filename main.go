package main

import (
	"fmt"

	"github.com/bob17/capp/internal/config"
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

	for _, pcap := range defCfg.PcapFiles {
		fmt.Printf("Path to pcap file: %s \n", pcap)
	}

	fmt.Println("configuration file content successfully retrieved")
}
