package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	PcapFiles []string `yaml:"pcap_files"`
	LogLevel  string   `yaml:"log_level"`
	LogFile   string   `yaml:"log_file"`
}

func GetDefaultConfig() *Config {
	return &Config{
		PcapFiles: []string{},
		LogLevel:  "info",
		LogFile:   "pcap_analysis.log",
	}
}

func (c *Config) ValidateCFG() error {
	if len(c.PcapFiles) == 0 {
		return fmt.Errorf("No pcap file provided to analyze")
	}

	for _, pcapFile := range c.PcapFiles {
		if _, err := os.Stat(pcapFile); os.IsNotExist(err) {
			fmt.Println("Invalid path for pcap file")
			return fmt.Errorf("pcap file path is invalid or pcap file doesn't exist at %s: ERROR > > > %v", pcapFile, err)
		}
	}

	logLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
		"fatal": true,
	}

	if _, ok := logLevels[c.LogLevel]; !ok {
		return fmt.Errorf("invalid log level provided in configuration file: %s", c.LogLevel)
	}

	return nil
}

type YAMLConfigLoader struct{}

type ConfigLoader interface {
	LoadConfig(configPath string, cfg *Config) error
}

func (y *YAMLConfigLoader) LoadConfig(configPath string, cfg *Config) error {
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return fmt.Errorf("error while decoding content of yaml file to Config struct. :%v", err)
	}

	return nil
}
