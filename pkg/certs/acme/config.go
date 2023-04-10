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

package acme

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	configBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file '%s' (cause: %w)", path, err)
	}
	config := defaultConfig()
	err = yaml.Unmarshal(configBytes, config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal configuration file '%s' (cause: %w)", path, err)
	}
	for name, provider := range config.Providers {
		provider.Name = name
		config.Providers[name] = provider
	}
	for domain, domainConfig := range config.Domains {
		domainConfig.Domain = domain
		config.Domains[domain] = domainConfig
	}
	return config, nil
}

func defaultConfig() *Config {
	return &Config{
		Providers: make(map[string]Provider, 0),
		Domains:   make(map[string]DomainConfig, 0),
	}
}

type Config struct {
	Providers map[string]Provider     `yaml:"providers"`
	Domains   map[string]DomainConfig `yaml:"domains"`
}

type Provider struct {
	Name              string `yaml:"-"`
	URL               string `yaml:"url"`
	RegistrationEmail string `yaml:"registration_email"`
}

type DomainConfig struct {
	Domain            string                  `yaml:"-"`
	Http01Challenge   Http01ChallengeConfig   `yaml:"http-01"`
	TLSAPN01Challenge TLSAPN01ChallengeConfig `yaml:"tls-apn-01"`
}

type Http01ChallengeConfig struct {
	Enabled bool   `yaml:"enabled"`
	Iface   string `yaml:"iface"`
	Port    int    `ymal:"port"`
}

type TLSAPN01ChallengeConfig struct {
	Enabled bool   `yaml:"enabled"`
	Iface   string `yaml:"iface"`
	Port    int    `ymal:"port"`
}
