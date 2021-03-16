package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"go/ast"
	"go/parser"
	"go/token"

	"golang.org/x/tools/cover"
)

type CoverageTotal struct {
	Count     int     `json:"count"`
	Covered   int     `json:"covered"`
	Uncovered int     `json:"notcovered"`
	Percent   float64 `json:"percent"`
}

type CoverageTotals struct {
	Functions CoverageTotal `json:"functions,omitempty"`
	Lines     CoverageTotal `json:"lines,omitempty"`
	Regions   CoverageTotal `json:"regions,omitempty"`
}

type CoverageData struct {
	Totals CoverageTotals `json:"totals,omitempty"`
}

type PositionInterval struct {
	start token.Position
	end   token.Position
}

type CoverageSummary struct {
	Data    []CoverageData `json:"data,omitempty"`
	Type    string         `json:"type,omitempty"`
	Version string         `json:"version,omitempty"`
}

func isFunctionCovered(s token.Position, e token.Position, blocks []cover.ProfileBlock) bool {
	for _, b := range blocks {
		if b.StartLine >= s.Line && b.StartLine <= e.Line && b.EndLine >= s.Line && b.EndLine <= e.Line {
			if b.Count > 0 {
				return true
			}
		}
	}
	return false
}

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 {
		log.Fatalf("needs exactly one argument")
	}
	profiles, err := cover.ParseProfiles(flag.Args()[0])
	if err != nil {
		log.Fatalf("failed to parse profiles: %v", err)
	}
	r := CoverageSummary{}
	r.Type = "oss-fuzz.go.coverage.json.export"
	r.Version = "1.0.0"
	r.Data = make([]CoverageData, 1)
	for _, p := range profiles {
		fset := token.NewFileSet() // positions are relative to fset
		f, err := parser.ParseFile(fset, p.FileName, nil, 0)
		if err != nil {
			panic(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				startf := fset.Position(x.Pos())
				endf := fset.Position(x.End())
				r.Data[0].Totals.Functions.Count++
				if isFunctionCovered(startf, endf, p.Blocks) {
					r.Data[0].Totals.Functions.Covered++
				} else {
					r.Data[0].Totals.Functions.Uncovered++
				}
			case *ast.FuncDecl:
				startf := fset.Position(x.Pos())
				endf := fset.Position(x.End())
				r.Data[0].Totals.Functions.Count++
				if isFunctionCovered(startf, endf, p.Blocks) {
					r.Data[0].Totals.Functions.Covered++
				} else {
					r.Data[0].Totals.Functions.Uncovered++
				}
			}
			return true
		})

		for _, b := range p.Blocks {
			r.Data[0].Totals.Regions.Count++
			if b.Count > 0 {
				r.Data[0].Totals.Regions.Covered++
			} else {
				r.Data[0].Totals.Regions.Uncovered++
			}

			r.Data[0].Totals.Lines.Count += b.NumStmt
			if b.Count > 0 {
				r.Data[0].Totals.Lines.Covered += b.NumStmt
			} else {
				r.Data[0].Totals.Lines.Uncovered += b.NumStmt
			}
		}
	}
	r.Data[0].Totals.Regions.Percent = float64(100*r.Data[0].Totals.Regions.Covered) / float64(r.Data[0].Totals.Regions.Count)
	r.Data[0].Totals.Lines.Percent = float64(100*r.Data[0].Totals.Lines.Covered) / float64(r.Data[0].Totals.Lines.Count)
	r.Data[0].Totals.Functions.Percent = float64(100*r.Data[0].Totals.Functions.Covered) / float64(r.Data[0].Totals.Functions.Count)
	o, _ := json.Marshal(r)
	fmt.Printf(string(o))
}
