package fuzzing

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	"github.com/linkerd/linkerd2/pkg/healthcheck"
	"github.com/linkerd/linkerd2/pkg/util"
	corev1 "k8s.io/api/core/v1"
)

func FuzzParsePorts(data []byte) int {
	_, _ = util.ParsePorts(string(data))
	return 1
}

func FuzzParseContainerOpaquePorts(data []byte) int {
	f := fuzz.NewConsumer(data)

	qtyOfContainers, err := f.GetInt()
	if err != nil {
		return 0
	}

	containers := make([]corev1.Container, 0)
	for i := 0; i < qtyOfContainers%20; i++ {
		newContainer := corev1.Container{}
		err = f.GenerateStruct(&newContainer)
		if err != nil {
			return 0
		}
		containers = append(containers, newContainer)
	}
	override, err := f.GetString()
	if err != nil {
		return 0
	}
	_ = util.ParseContainerOpaquePorts(override, containers)
	return 1
}

func FuzzHealthCheck(data []byte) int {
	f := fuzz.NewConsumer(data)
	options := &healthcheck.Options{}
	err := f.GenerateStruct(options)
	if err != nil {
		return 0
	}
	_ = healthcheck.NewHealthChecker([]healthcheck.CategoryID{healthcheck.KubernetesAPIChecks}, options)
	return 1
}
