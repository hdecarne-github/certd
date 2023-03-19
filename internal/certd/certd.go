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
	"os"
	"runtime/debug"

	"fmt"

	"github.com/alecthomas/kong"
	"github.com/hdecarne-github/certd/internal/buildinfo"
	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/internal/server"
	"github.com/rs/zerolog"
)

type cmdline struct {
	Version versionCmd `cmd:"" help:"Display version and exit"`
	Server  serverCmd  `cmd:"" help:"Run server"`
	Verbose bool       `help:"Enable verbose output"`
	Debug   bool       `help:"Enable debug output"`
	Ansi    bool       `help:"Enable ANSI colored output"`
	logger  *zerolog.Logger
}

type versionCmd struct{}

func (cmd *versionCmd) Run(cmdline *cmdline) error {
	fmt.Println(buildinfo.FullVersion())
	if cmdline.Debug {
		buildinfo, ok := debug.ReadBuildInfo()
		if ok {
			fmt.Println("build info:")
			fmt.Print(buildinfo.String())
		}
	}
	return nil
}

type serverCmd struct {
	Listen string `help:"The listen address (defaults to localhost:10509)"`
}

const defaultListen string = "localhost:10509"

func (cmd *serverCmd) Run(cmdline *cmdline) error {
	applyGlobalConfig(cmdline)
	listen := cmdline.Server.Listen
	if listen == "" {
		listen = defaultListen
	}
	return server.Run(listen)
}

func applyGlobalConfig(cmdline *cmdline) {
	logger := logging.NewConsoleLogger(os.Stdout, cmdline.Ansi)
	if cmdline.Debug {
		logging.UpdateRootLogger(logger, zerolog.DebugLevel)
	} else if cmdline.Verbose {
		logging.UpdateRootLogger(logger, zerolog.InfoLevel)
	}
}

var cmd cmdline = cmdline{logger: logging.RootLogger()}

func Run() error {
	err := kong.Parse(&cmd).Run(&cmd)
	if err != nil {
		cmd.logger.Error().Err(err).Msgf("certd command failed\n\tcause: %v", err)
	}
	return err
}
