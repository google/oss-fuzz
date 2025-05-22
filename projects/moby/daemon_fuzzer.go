// Copyright 2022 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package daemon

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/moby/sys/mount"
	"github.com/sirupsen/logrus"

	"github.com/docker/docker/api/types/backend"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/daemon/images"
	"github.com/docker/docker/image"
	dockerreference "github.com/docker/docker/reference"
	"github.com/opencontainers/go-digest"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	logrus.SetLevel(logrus.ErrorLevel)
}

func IsJSON(input []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(input, &js) == nil
}

func FuzzDaemonSimple(data []byte) int {
	if os.Getuid() != 0 {
		return -1
	}

	f := fuzz.NewConsumer(data)

	// reference store
	referenceStoreJson, err := f.GetBytes()
	if err != nil {
		return 0
	}

	if !IsJSON(referenceStoreJson) {
		return 0
	}
	// referenceStore
	rsDir, err := os.MkdirTemp("", "referenceStore")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(rsDir)
	jsonFile := filepath.Join(rsDir, "repositories.json")
	err = os.WriteFile(jsonFile, referenceStoreJson, 0o666)
	if err != nil {
		panic(err)
	}
	rStore, err := dockerreference.NewReferenceStore(jsonFile)
	if err != nil {
		return 0
	}
	// end reference store

	testRoot, err := os.MkdirTemp("", "test-dir")
	if err != nil {
		return 0
	}
	defer os.RemoveAll(testRoot)
	cfg := &config.Config{}

	err = mount.MakePrivate(testRoot)
	if err != nil {
		return 0
	}
	defer mount.Unmount(testRoot)

	cfg.ExecRoot = filepath.Join(testRoot, "exec")
	cfg.Root = filepath.Join(testRoot, "daemon")

	err = os.Mkdir(cfg.ExecRoot, 0755)
	if err != nil {
		return 0
	}
	err = os.Mkdir(cfg.Root, 0755)
	if err != nil {
		return 0
	}

	imgStoreDir, err := os.MkdirTemp("", "images-fs-store")
	if err != nil {
		panic(err)
	}

	fsBackend, err := image.NewFSStoreBackend(imgStoreDir)
	if err != nil {
		panic(err)
	}

	defer os.RemoveAll(imgStoreDir)

	is, err := image.NewImageStore(fsBackend, nil)
	if err != nil {
		panic(err)
	}

	d := &Daemon{
		root:         cfg.Root,
		imageService: images.NewImageService(images.ImageServiceConfig{ReferenceStore: rStore, ImageStore: is}),
		containers:   container.NewMemoryStore(),
	}

	configStore := &configStore{Config: *cfg}
	d.configStore.Store(configStore)

	containersReplica, err := container.NewViewDB()
	if err != nil {
		panic(err)
	}

	d.containersReplica = containersReplica

	var noOfCalls int
	noOfCalls, err = f.GetInt()
	if err != nil {
		return 0
	}
	if noOfCalls < 2 {
		noOfCalls = 2
	}
	for i := 0; i < noOfCalls%10; i++ {
		typeOfCall, err := f.GetInt()
		if err != nil {
			return 0
		}
		//fmt.Println("calling ", typeOfCall%8)
		switch typeOfCall % 11 {
		case 0:
			refOrID, err := f.GetString()
			if err != nil {
				return -1
			}
			if refOrID == "" {
				continue
			}
			options := backend.GetImageOpts{}
			f.GenerateStruct(&options)
			_, _ = d.imageService.GetImage(context.Background(), refOrID, options)
		case 1:

			getContainer, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = d.GetContainer(getContainer)
		case 2:
			c := &container.Container{}
			f.GenerateStruct(c)
			if c.ID == "" {
				continue
			}
			c.State = container.NewState()
			c.ExecCommands = container.NewExecStore()
			d.containers.Add(c.ID, c)
		case 3:
			refOrID, err := f.GetString()
			if err != nil {
				return -1
			}
			d.containers.Delete(refOrID)
		case 4:
			d.containers.List()
		case 5:
			d.containers.Size()
		case 6:
			prefixOrName, err := f.GetString()
			if err != nil {
				return -1
			}
			c := &backend.ContainerAttachConfig{}
			f.GenerateStruct(c)
			d.ContainerAttach(prefixOrName, c)
		case 7:
			imageConfig, err := f.GetBytes()
			if err != nil {
				return 0
			}
			parent, err := f.GetString()
			if err != nil {
				return 0
			}
			dig := digest.FromBytes([]byte("fuzz"))
			_, _ = d.imageService.CreateImage(context.Background(), imageConfig, parent, dig)
		case 8:
			params := &backend.ContainerCreateConfig{}
			f.GenerateStruct(params)
			_, _ = d.ContainerCreate(context.Background(), *params)
		case 9:
			name, err := f.GetString()
			if err != nil {
				return 0
			}
			_, _ = d.ContainerChanges(context.Background(), name)
		}
	}
	return 1
}
