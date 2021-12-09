// Copyright 2021 Google LLC
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
//

package destination

import (
	"testing"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
	pb "github.com/linkerd/linkerd2-proxy-api/go/destination"
	"github.com/linkerd/linkerd2/controller/api/destination/watcher"
	"github.com/linkerd/linkerd2/controller/api/util"
	sp "github.com/linkerd/linkerd2/controller/gen/apis/serviceprofile/v1alpha2"
	ts "github.com/servicemeshinterface/smi-sdk-go/pkg/apis/split/v1alpha1"
	logging "github.com/sirupsen/logrus"
)

func init() {
	testing.Init()
}

func FuzzAdd(data []byte) int {
	f := fuzz.NewConsumer(data)
	set := watcher.AddressSet{}
	err := f.GenerateStruct(&set)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	_, translator := makeEndpointTranslator(t)
	translator.Add(set)
	translator.Remove(set)
	return 1
}

func FuzzGetProfile(data []byte) int {
	f := fuzz.NewConsumer(data)
	dest := &pb.GetDestination{}
	err := f.GenerateStruct(dest)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	server := makeServer(t)
	stream := &bufferingGetProfileStream{
		updates:          []*pb.DestinationProfile{},
		MockServerStream: util.NewMockServerStream(),
	}
	stream.Cancel()
	_ = server.GetProfile(dest, stream)
	return 1
}

func FuzzProfileTranslatorUpdate(data []byte) int {
	f := fuzz.NewConsumer(data)
	profile := &sp.ServiceProfile{}
	err := f.GenerateStruct(profile)
	if err != nil {
		return 0
	}
	t := &testing.T{}
	mockGetProfileServer := &mockDestinationGetProfileServer{profilesReceived: []*pb.DestinationProfile{}}

	translator := &profileTranslator{
		stream: mockGetProfileServer,
		log:    logging.WithField("test", t.Name()),
	}
	translator.Update(profile)
	return 1
}

func FuzzUpdateTrafficSplit(data []byte) int {
	f := fuzz.NewConsumer(data)
	split := &ts.TrafficSplit{}
	err := f.GenerateStruct(split)
	if err != nil {
		return 0
	}
	listener := watcher.NewBufferingProfileListener()
	adaptor := newTrafficSplitAdaptor(listener, watcher.ServiceID{Name: "foo", Namespace: "ns"}, watcher.Port(80), "cluster.local")

	adaptor.UpdateTrafficSplit(split)
	return 1
}
