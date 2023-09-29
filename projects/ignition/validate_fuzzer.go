package validate

import (
	"github.com/coreos/vcontext/report"
)

func mangleReport(r *report.Report) {
	for i := range r.Entries {
		if sp := r.Entries[i].Marker.StartP; sp != nil {
			sp.Index = 0
		}
		r.Entries[i].Marker.EndP = nil
	}
}

func FuzzValidate(data []byte) int {
	r := ValidateWithContext(struct{}{}, data)
	mangleReport(&r)
	return 1
}
