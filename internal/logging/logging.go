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

package logging

import (
	"log"
	"os"

	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
)

var rootLogger = NewConsoleLogger(os.Stdout, false)

func UpdateRootLogger(logger *zerolog.Logger, level zerolog.Level) {
	zerolog.SetGlobalLevel(level)
	rootLogger = logger
	log.SetFlags(0)
	log.SetOutput(logger)
	rootLogger.Info().Msg("root logger configured")
}

func RootLogger() *zerolog.Logger {
	return rootLogger
}

func NewConsoleLogger(out *os.File, forceColor bool) *zerolog.Logger {
	color := forceColor
	if !color {
		color = isatty.IsTerminal(out.Fd())
	}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: out, NoColor: !color}).With().Timestamp().Logger()
	return &logger
}

func init() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.WarnLevel)
}
