package fuzzing

import (
	fuzz "github.com/AdaLogics/go-fuzz-headers"

	"vitess.io/vitess/go/vt/sqlparser"
	"testing"
)

func FuzzEqualsSQLNode(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 10 {
			return
		}
		f := fuzz.NewConsumer(data)
		query1, err := f.GetSQLString()
		if err != nil {
			return
		}
		query2, err := f.GetSQLString()
		if err != nil {
			return
		}
		inA, err := sqlparser.Parse(query1)
		if err != nil {
			return
		}
		inB, err := sqlparser.Parse(query2)
		if err != nil {
			return
		}

		// There are 3 targets in this fuzzer:
		// 1) sqlparser.EqualsSQLNode
		// 2) sqlparser.CloneSQLNode
		// 3) sqlparser.VisitSQLNode

		// Target 1:
		identical := sqlparser.EqualsSQLNode(inA, inA)
		if !identical {
			panic("Should be identical")
		}
		identical = sqlparser.EqualsSQLNode(inB, inB)
		if !identical {
			panic("Should be identical")
		}

		// Target 2:
		newSQLNode := sqlparser.CloneSQLNode(inA)
		if !sqlparser.EqualsSQLNode(inA, newSQLNode) {
			panic("These two nodes should be identical")
		}

		// Target 3:
		_ = sqlparser.VisitSQLNode(inA, func(node sqlparser.SQLNode) (bool, error) { return false, nil })
	})
}
