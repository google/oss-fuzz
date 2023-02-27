// Copyright 2023 Google LLC
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
	Functions      CoverageTotal `json:"functions,omitempty"`
	Lines          CoverageTotal `json:"lines,omitempty"`
	Regions        CoverageTotal `json:"regions,omitempty"`
	Instantiations CoverageTotal `json:"instantiations,omitempty"`
	Branches       CoverageTotal `json:"branches,omitempty"`
}

type CoverageFile struct {
	Summary  CoverageTotals `json:"summary,omitempty"`
	Filename string         `json:"filename,omitempty"`
}

type CoverageData struct {
	Totals CoverageTotals `json:"totals,omitempty"`
	Files  []CoverageFile `json:"files,omitempty"`
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

func computePercent(s *CoverageTotals) {
	if s.Regions.Count > 0 {
		s.Regions.Percent = float64(100*s.Regions.Covered) / float64(s.Regions.Count)
	}
	if s.Lines.Count > 0 {
		s.Lines.Percent = float64(100*s.Lines.Covered) / float64(s.Lines.Count)
	}
	if s.Functions.Count > 0 {
		s.Functions.Percent = float64(100*s.Functions.Covered) / float64(s.Functions.Count)
	}
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
	r.Version = "2.0.1"
	r.Data = make([]CoverageData, 1)
	for _, p := range profiles {
		fset := token.NewFileSet() // positions are relative to fset
		f, err := parser.ParseFile(fset, p.FileName, nil, 0)
		if err != nil {
			log.Printf("failed to parse go file: %v", err)
			continue
		}
		fileCov := CoverageFile{}
		fileCov.Filename = p.FileName
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				startf := fset.Position(x.Pos())
				endf := fset.Position(x.End())
				fileCov.Summary.Functions.Count++
				if isFunctionCovered(startf, endf, p.Blocks) {
					fileCov.Summary.Functions.Covered++
				} else {
					fileCov.Summary.Functions.Uncovered++
				}
			case *ast.FuncDecl:
				startf := fset.Position(x.Pos())
				endf := fset.Position(x.End())
				fileCov.Summary.Functions.Count++
				if isFunctionCovered(startf, endf, p.Blocks) {
					fileCov.Summary.Functions.Covered++
				} else {
					fileCov.Summary.Functions.Uncovered++
				}
			}
			return true
		})

		for _, b := range p.Blocks {
			fileCov.Summary.Regions.Count++
			if b.Count > 0 {
				fileCov.Summary.Regions.Covered++
			} else {
				fileCov.Summary.Regions.Uncovered++
			}

			fileCov.Summary.Lines.Count += b.NumStmt
			if b.Count > 0 {
				fileCov.Summary.Lines.Covered += b.NumStmt
			} else {
				fileCov.Summary.Lines.Uncovered += b.NumStmt
			}
		}
		r.Data[0].Totals.Regions.Count += fileCov.Summary.Regions.Count
		r.Data[0].Totals.Regions.Covered += fileCov.Summary.Regions.Covered
		r.Data[0].Totals.Regions.Uncovered += fileCov.Summary.Regions.Uncovered
		r.Data[0].Totals.Lines.Count += fileCov.Summary.Lines.Count
		r.Data[0].Totals.Lines.Covered += fileCov.Summary.Lines.Covered
		r.Data[0].Totals.Lines.Uncovered += fileCov.Summary.Lines.Uncovered
		r.Data[0].Totals.Functions.Count += fileCov.Summary.Functions.Count
		r.Data[0].Totals.Functions.Covered += fileCov.Summary.Functions.Covered
		r.Data[0].Totals.Functions.Uncovered += fileCov.Summary.Functions.Uncovered

		computePercent(&fileCov.Summary)
		r.Data[0].Files = append(r.Data[0].Files, fileCov)
	}

	computePercent(&r.Data[0].Totals)
	o, err := json.Marshal(r)
	if err != nil {
		log.Fatalf("failed to generate json: %v", err)
	}
	fmt.Printf(string(o))
}
