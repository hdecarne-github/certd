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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDefaultHandler(t *testing.T) {
	readWriteState(t)
}
func TestFSHandler(t *testing.T) {
	stateDir, err := os.MkdirTemp("", "state")
	require.NoError(t, err)
	defer os.RemoveAll(stateDir)
	UpdateHandler(NewFSHandler(stateDir))
	readWriteState(t)
}

func readWriteState(t *testing.T) {
	const stateFile = "state.txt"
	const stateData = "state"
	_, err := Read(stateFile)
	require.ErrorIs(t, err, os.ErrNotExist)
	err = Write(stateFile, []byte(stateData))
	require.NoError(t, err)
	err = Write(stateFile, []byte(stateData))
	require.NoError(t, err)
	data, err := Read(stateFile)
	require.NoError(t, err)
	require.Equal(t, stateData, string(data))
}

func TestFSHandlerChecks(t *testing.T) {
	stateDir, err := os.MkdirTemp("", "state")
	require.NoError(t, err)
	defer os.RemoveAll(stateDir)
	UpdateHandler(NewFSHandler(stateDir))
	_, err = Read("../certd/certd.go")
	require.Error(t, err)
	err = Write(filepath.Join(os.TempDir(), "test.txt"), []byte("test"))
	require.Error(t, err)
}
