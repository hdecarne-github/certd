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

package certd

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/alecthomas/kong"
	"github.com/hdecarne-github/certd/internal/buildinfo"
	"github.com/hdecarne-github/certd/internal/config"
	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/internal/server"
	"github.com/rs/zerolog"
)

type Runner interface {
	Version() error
	Server(config *config.ServerConfig) error
}

type cmdline struct {
	Version versionCmd `cmd:"" help:"Display version and exit"`
	Server  serverCmd  `cmd:"" help:"Run server"`
	Verbose bool       `help:"Enable verbose output"`
	Debug   bool       `help:"Enable debug output"`
	ANSI    bool       `help:"Force ANSI colored output"`
	logger  *zerolog.Logger
	runner  Runner
}

type versionCmd struct{}

func (cmd *versionCmd) Run(cmdline *cmdline) error {
	return cmdline.runner.Version()
}

type serverCmd struct {
	Config    string `help:"The configuration file to use (defaults to /etc/certd/certd.yaml)"`
	ServerURL string `help:"The server URL to listen on (defaults to configuration file value)"`
	StorePath string `help:"The store path to use (defaults to configuration file value)"`
	StatePath string `help:"The state path to use (defaults to configuration file value)"`
}

const defaultServerConfigPath = "/etc/certd/certd.yaml"

func (cmd *serverCmd) Run(cmdline *cmdline) error {
	configPath := cmd.Config
	if configPath == "" {
		configPath = defaultServerConfigPath
	}
	config, err := config.Load(configPath)
	if err != nil {
		return err
	}
	mergeServerCmdline(config, cmdline)
	applyGlobalConfig(config)
	return cmdline.runner.Server(&config.Server)
}

func mergeServerCmdline(config *config.Config, cmdline *cmdline) {
	mergeGlobalCmdline(config, cmdline)
	if cmdline.Server.ServerURL != "" {
		config.Server.ServerURL = cmdline.Server.ServerURL
	}
	if cmdline.Server.StorePath != "" {
		config.Server.StorePath = cmdline.Server.StorePath
	}
	if cmdline.Server.StatePath != "" {
		config.Server.StatePath = cmdline.Server.StatePath
	}
}

func mergeGlobalCmdline(config *config.Config, cmdline *cmdline) {
	if cmdline.Debug {
		config.Debug = true
	}
	if cmdline.Verbose {
		config.Verbose = true
	}
	if cmdline.ANSI {
		config.ANSI = true
	}
}

func applyGlobalConfig(config *config.Config) {
	logger := logging.NewConsoleLogger(os.Stdout, config.ANSI)
	if config.Debug {
		logging.UpdateRootLogger(logger, zerolog.DebugLevel)
	} else if config.Verbose {
		logging.UpdateRootLogger(logger, zerolog.InfoLevel)
	} else {
		logging.UpdateRootLogger(logger, zerolog.WarnLevel)
	}
}

func Run(runner Runner) error {
	var cmd *cmdline
	if runner != nil {
		cmd = &cmdline{
			logger: logging.RootLogger(),
			runner: runner,
		}
	} else {
		cmdRunner := cmdlineRunner{
			cmdline: cmdline{
				logger: logging.RootLogger(),
			},
		}
		cmdRunner.runner = &cmdRunner
		cmd = &cmdRunner.cmdline
	}
	err := kong.Parse(cmd).Run(cmd)
	if err != nil {
		cmd.logger.Error().Err(err).Msgf("certd command failed (cause: %v)", err)
	}
	return err
}

type cmdlineRunner struct {
	cmdline
}

func (runner *cmdlineRunner) Version() error {
	fmt.Println(buildinfo.FullVersion())
	if runner.Debug {
		buildinfo, ok := debug.ReadBuildInfo()
		if ok {
			fmt.Println("build info:")
			fmt.Print(buildinfo.String())
		}
	}
	return nil
}

func (runner *cmdlineRunner) Server(config *config.ServerConfig) error {
	return server.Run(config)
}
