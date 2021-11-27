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

package identity

import (
	"context"
	pb "github.com/linkerd/linkerd2-proxy-api/go/identity"
	"github.com/linkerd/linkerd2/pkg/tls"

	fuzz "github.com/AdaLogics/go-fuzz-headers"
)

func FuzzServiceCertify(data []byte) int {
	f := fuzz.NewConsumer(data)
	req := &pb.CertifyRequest{}
	err := f.GenerateStruct(req)
	if err != nil {
		return 0
	}

	svc := NewService(&fakeValidator{"successful-result", nil}, nil, nil, nil, "", "", "")
	svc.updateIssuer(&fakeIssuer{tls.Crt{}, nil})

	_, _ = svc.Certify(context.Background(), req)
	return 1
}
