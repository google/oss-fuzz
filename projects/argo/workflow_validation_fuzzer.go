package validate

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"
	wfv1 "github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	fakewfclientset "github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned/fake"
	"github.com/argoproj/argo-workflows/v3/workflow/templateresolution"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	wfClientsetFuzz   = fakewfclientset.NewSimpleClientset()
	wftmplGetterFuzz  = templateresolution.WrapWorkflowTemplateInterface(wfClientsetFuzz.ArgoprojV1alpha1().WorkflowTemplates(metav1.NamespaceDefault))
	cwftmplGetterFuzz = templateresolution.WrapClusterWorkflowTemplateInterface(wfClientsetFuzz.ArgoprojV1alpha1().ClusterWorkflowTemplates())
)

func FuzzValidateWorkflow(data []byte) int {
	f := fuzz.NewConsumer(data)
	wf := &wfv1.Workflow{}
	err := f.GenerateStruct(wf)
	if err != nil {
		return 0
	}
	opts := ValidateOpts{}
	_, _ = ValidateWorkflow(wftmplGetterFuzz, cwftmplGetterFuzz, wf, opts)
	return 1
}
