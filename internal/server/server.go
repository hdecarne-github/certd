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
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hdecarne-github/certd/internal/config"
	"github.com/hdecarne-github/certd/internal/ginextra"
	"github.com/hdecarne-github/certd/internal/logging"
	"github.com/hdecarne-github/certd/internal/state"
	"github.com/hdecarne-github/certd/pkg/certs/fsstore"
	"github.com/rs/zerolog"
)

//go:embed all:* htdocs/*
var htdocs embed.FS

func htdocsFS() (fs.FS, error) {
	return fs.Sub(htdocs, "htdocs")
}

func Run(config *config.ServerConfig) error {
	logger := logging.RootLogger().With().Str("server", config.ServerURL).Logger()
	s := &server{
		config: config,
		logger: &logger,
	}
	return s.Run()
}

type server struct {
	config *config.ServerConfig
	store  *fsstore.FSStore
	logger *zerolog.Logger
}

func (s *server) Run() error {
	s.logger.Info().Msg("Starting server...")
	state.UpdateHandler(state.NewFSHandler(s.config.StatePath))
	err := s.prepareStore()
	if err != nil {
		return err
	}
	_, listen, prefix, err := s.splitServerURL()
	if err != nil {
		return err
	}
	router, err := s.setupRouter(prefix)
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

func (s *server) prepareStore() error {
	storePath := config.ResolveConfigPath(s.config.BasePath, s.config.StorePath)
	_, err := os.Stat(storePath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	s.logger.Info().Msgf("Preparing store '%s'...", storePath)
	if err != nil {
		s.store, err = fsstore.Init(storePath)
	} else {
		s.store, err = fsstore.Open(storePath)
	}
	return err
}

const httpPrefix = "http://"
const httpsPrefix = "https://"

func (s *server) splitServerURL() (bool, string, string, error) {
	remaining := s.config.ServerURL
	var tls bool
	if strings.HasPrefix(remaining, httpPrefix) {
		tls = false
		remaining = strings.TrimPrefix(remaining, httpPrefix)
	} else if strings.HasPrefix(remaining, httpsPrefix) {
		tls = true
		remaining = strings.TrimPrefix(remaining, httpsPrefix)
	} else {
		return false, "", "", fmt.Errorf("invalid server URL '%s'; unrecognized protocol", s.config.ServerURL)
	}
	remainings := strings.SplitN(remaining, "/", 2)
	listen := remainings[0]
	prefix := "/"
	if len(remainings) == 2 {
		prefix = prefix + remainings[1]
	}
	prefix = strings.TrimSuffix(prefix, "/")
	return tls, listen, prefix, nil
}

func (s *server) setupRouter(prefix string) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(ginextra.Logger(s.logger), gin.Recovery())
	htdocs, err := htdocsFS()
	if err != nil {
		return nil, fmt.Errorf("unexpected error: %w", err)
	}
	router.GET(prefix+"/api/shutdown", s.shutdown)
	router.GET(prefix+"/api/about", s.about)
	router.GET(prefix+"/api/store/entries", s.storeEntries)
	router.GET(prefix+"/api/store/entry/details/:name", s.storeEntryDetails)
	router.GET(prefix+"/api/store/cas", s.storeCAs)
	router.GET(prefix+"/api/store/local/issuers", s.storeLocalIssuers)
	router.PUT(prefix+"/api/store/local/generate", s.storeLocalGenerate)
	router.PUT(prefix+"/api/store/remote/generate", s.storeRemoteGenerate)
	router.PUT(prefix+"/api/store/acme/generate", s.storeACMEGenerate)
	router.NoRoute(ginextra.StaticFS(prefix, http.FS(htdocs)))
	return router, nil
}

type serverErrorResponse struct {
	Message string `json:"message"`
}

func (s *server) sendError(c *gin.Context, status int, message string) {
	errorResponse := &serverErrorResponse{
		Message: message,
	}
	c.JSON(status, errorResponse)
}
