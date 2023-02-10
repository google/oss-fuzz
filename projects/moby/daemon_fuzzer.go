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
	"os"
	"path/filepath"

	"github.com/moby/sys/mount"
	"github.com/sirupsen/logrus"

	imagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/container"
	"github.com/docker/docker/daemon/config"
	"github.com/docker/docker/daemon/images"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func init() {
	logrus.SetLevel(logrus.ErrorLevel)
}

func FuzzDaemonSimple(data []byte) int {
	if os.Getuid() != 0 {
		return -1
	}

	f := fuzz.NewConsumer(data)
	c := &container.Container{}
	f.GenerateStruct(c)
	if c.ID == "" {
		return 0
	}

	options := imagetypes.GetImageOpts{}
	f.GenerateStruct(&options)

	refOrID, err := f.GetString()
	if err != nil || refOrID == "" {
		return -1
	}

	getContainer, err := f.GetString()
	if err != nil {
		return 0
	}

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

	d := &Daemon{configStore: cfg,
		root:         cfg.Root,
		imageService: images.NewImageService(images.ImageServiceConfig{}),
	}

	store := container.NewMemoryStore()
	store.Add(c.ID, c)

	containersReplica, err := container.NewViewDB()
	if err != nil {
		panic(err)
	}

	d.containers = store
	d.containersReplica = containersReplica

	_, _ = d.imageService.GetImage(context.Background(), refOrID, options)
	_, _ = d.GetContainer(getContainer)
	return 1
}
