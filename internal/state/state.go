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

package state

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/hdecarne-github/certd/internal/logging"
)

var stateHandler Handler = &defaultHandler{store: make(map[string][]byte, 0)}
var stateMutex sync.RWMutex

func UpdateHandler(handler Handler) {
	logging.RootLogger().Info().Msgf("Using %s", handler)
	stateHandler = handler
}

type Handler interface {
	Write(path string, data []byte) error
	Read(path string) ([]byte, error)
	String() string
}

func Write(path string, data []byte) error {
	stateMutex.Lock()
	defer stateMutex.Unlock()
	return stateHandler.Write(path, data)
}

func Read(path string) ([]byte, error) {
	stateMutex.RLock()
	defer stateMutex.RUnlock()
	return stateHandler.Read(path)
}

type defaultHandler struct {
	store map[string][]byte
}

func (handler *defaultHandler) Write(path string, data []byte) error {
	written := data
	handler.store[path] = written
	return nil
}

func (handler *defaultHandler) Read(path string) ([]byte, error) {
	read := handler.store[path]
	if read == nil {
		return nil, os.ErrNotExist
	}
	return read, nil
}

func (handler *defaultHandler) String() string {
	return "memory state handler"
}

func NewFSHandler(stateDir string) Handler {
	return &fsHandler{basePath: stateDir}
}

type fsHandler struct {
	basePath string
}

const fsHandlerDirMode fs.FileMode = 0700
const fsHandlerFileMode fs.FileMode = 0600

func (handler *fsHandler) Write(path string, data []byte) error {
	fullPath, err := handler.fullPath(path)
	if err != nil {
		return err
	}
	err = os.MkdirAll(filepath.Dir(fullPath), fsHandlerDirMode)
	if err != nil {
		return fmt.Errorf("failed to create directory path for for state file '%s' (cause: %w)", fullPath, err)
	}
	err = os.WriteFile(fullPath, data, fsHandlerFileMode)
	if err != nil {
		return fmt.Errorf("failed to write state file '%s' (cause: %w)", fullPath, err)
	}
	return nil
}

func (handler *fsHandler) Read(path string) ([]byte, error) {
	fullPath, err := handler.fullPath(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(fullPath)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("failed to read state file '%s' (cause: %w)", fullPath, err)
	}
	return data, err
}

func (handler *fsHandler) fullPath(path string) (string, error) {
	basePath, err := filepath.Abs(handler.basePath)
	if err != nil {
		return "", fmt.Errorf("failed to determine absolute path for state directory '%s' (cause: %w)", handler.basePath, err)
	}
	if filepath.IsAbs(path) {
		return "", fmt.Errorf("illegal absolute state file path '%s'", path)
	}
	fullPath, err := filepath.Abs(filepath.Join(basePath, path))
	if err != nil {
		return "", fmt.Errorf("failed to determine absolute path for state file '%s' (cause: %w)", path, err)
	}
	if !strings.HasPrefix(fullPath, basePath) {
		return "", fmt.Errorf("illegal state file path '%s'", path)
	}
	return fullPath, nil
}

func (handler *fsHandler) String() string {
	return fmt.Sprintf("FS state handler; state path: '%s'", handler.basePath)
}
