// Copyright 2022 Google LLC
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

package net

import (
	"context"
	"os"
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"

	pkgnet "knative.dev/networking/pkg/apis/networking"
	"knative.dev/serving/pkg/queue"

	"knative.dev/pkg/injection"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"

	"knative.dev/pkg/controller"
)

func NewFuzzLogger() *zap.SugaredLogger {
	var config zap.Config
	config = zap.NewProductionConfig()
	// Config customization goes here if any
	config.OutputPaths = []string{os.DevNull}
	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	return logger.Named("knative-log").Sugar()
}

func FuzzNewRevisionThrottler(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		ff := fuzz.NewConsumer(data)

		revName := types.NamespacedName{}
		ff.GenerateStruct(&revName)

		containerConcurrency, err := ff.GetInt()
		if err != nil {
			t.Skip()
		}
		params := queue.BreakerParams{}
		ff.GenerateStruct(&params)
		if params.QueueDepth <= 0 {
			t.Skip()
		}
		if params.MaxConcurrency < 0 {
			t.Skip()
		}
		if params.InitialCapacity < 0 || params.InitialCapacity > params.MaxConcurrency {
			t.Skip()
		}
		logger := NewFuzzLogger()
		rt := newRevisionThrottler(revName, containerConcurrency%10, pkgnet.ServicePortNameHTTP1, params, logger)

		//ctx := context.Background()
		ctx, cancel := SetupFakeContextWithCancel()
		defer cancel()
		throttler := newTestThrottler(ctx)
		throttler.revisionThrottlers[revName] = rt

		update := revisionDestsUpdate{
			Rev:           revName,
			ClusterIPDest: "",
			Dests:         sets.NewString("ip3", "ip2", "ip1"),
		}
		throttler.handleUpdate(update)
	})
}

func SetupFakeContextWithCancel() (context.Context, context.CancelFunc) {
	ctx, c := context.WithCancel(context.Background())
	ctx = controller.WithEventRecorder(ctx, record.NewFakeRecorder(1000))
	ctx, _ = injection.Fake.SetupInformers(ctx, &rest.Config{})
	return ctx, c
}
