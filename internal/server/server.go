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

package server

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hdecarne-github/certd/internal/buildinfo"
	"github.com/hdecarne-github/certd/internal/ginextra"
	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/rs/zerolog"
)

//go:embed all:* htdocs/*
var htdocs embed.FS

func htdocsFS() (fs.FS, error) {
	return fs.Sub(htdocs, "htdocs")
}

func Run(listen string) error {
	logger := logging.RootLogger().With().Str("server", listen).Logger()
	s := &server{
		logger: &logger,
	}
	return s.Run(listen)
}

type server struct {
	logger *zerolog.Logger
}

func (s *server) Run(listen string) error {
	s.logger.Info().Msg("Starting server...")
	router, err := s.setup()
	if err != nil {
		return err
	}
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	sigintCtx, cancelListenAndServe := context.WithCancel(context.Background())
	go func() {
		<-sigint
		s.logger.Info().Msg("SIGINT received; stopping server...")
		cancelListenAndServe()
	}()
	httpServer := &http.Server{
		Addr:    listen,
		Handler: router,
	}
	go func() {
		err := httpServer.ListenAndServe()
		if err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msgf("Server failure: %v", err)
		}
	}()
	s.logger.Info().Msg("Listening...")
	<-sigintCtx.Done()
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), time.Second)
	defer cancelShutdown()
	err = httpServer.Shutdown(shutdownCtx)
	if err == nil {
		s.logger.Info().Msg("Shutdown complete")
	} else {
		return fmt.Errorf("shutdown failure: %w", err)
	}
	return nil
}

func (s *server) setup() (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(ginextra.Logger(s.logger), gin.Recovery())
	htdocs, err := htdocsFS()
	if err != nil {
		return nil, fmt.Errorf("unexpected error: %w", err)
	}
	router.GET("/api/about", s.about)
	router.NoRoute(ginextra.StaticFS(http.FS(htdocs)))
	return router, nil
}

type aboutResponse struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

func (s *server) about(c *gin.Context) {
	about := &aboutResponse{
		Version:   buildinfo.Version(),
		Timestamp: buildinfo.Timestamp(),
	}
	c.JSON(http.StatusOK, about)
}
