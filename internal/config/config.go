/*
 * Copyright (c) 2023 Holger de Carne and contributors, All Rights Reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package config

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed config_defaults.yaml
var configDefaults []byte

func Defaults() *Config {
	config := &Config{}
	err := yaml.Unmarshal(configDefaults, config)
	if err != nil {
		panic(err)
	}
	return config
}

func Load(path string) (*Config, error) {
	config := Defaults()
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file '%s' (cause: %w)", path, err)
	}
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration file '%s' (cause: %w)", path, err)
	}
	basePath := filepath.Dir(path)
	config.Server.BasePath = basePath
	config.CLI.BasePath = basePath
	return config, nil
}

type Config struct {
	Debug   bool         `yaml:"debug"`
	Verbose bool         `yaml:"verbose"`
	ANSI    bool         `yaml:"ansi"`
	Server  ServerConfig `yaml:"server"`
	CLI     CLIConfig    `yaml:"cli"`
}

type ServerConfig struct {
	BasePath   string `yaml:"-"`
	ServerURL  string `yaml:"server_url"`
	StorePath  string `yaml:"store_path"`
	StatePath  string `yaml:"state_path"`
	ACMEConfig string `yaml:"acme_config"`
}

type CLIConfig struct {
	BasePath  string `yaml:"-"`
	ServerURL string `yaml:"server_url"`
}

func ResolveConfigPath(basePath string, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(basePath, path)
}
