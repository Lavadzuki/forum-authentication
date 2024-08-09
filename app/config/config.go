package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type App struct {
	ServerAddress string `json:"server_address"`
}

type Http struct {
	Port         string `json:"port"`
	IdleTimeout  int    `json:"idle_timeout"`
	WriteTimeout int    `json:"write_timeout"`
	ReadTimeout  int    `json:"read_timeout"`
}

type Database struct {
	Dbname string `json:"dbname"`
}
type Config struct {
	App      `json:"app"`
	Http     `json:"http"`
	Database `json:"database"`
}

func InitConfig(path string) (Config, error) {
	var cfg Config
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open %s error: %s", path, err)
	}
	err = json.NewDecoder(file).Decode(&cfg)
	if err != nil {
		return Config{}, fmt.Errorf("decoding was failed")
	}
	return cfg, nil
}
