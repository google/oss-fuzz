// Copyright 2025 Google LLC
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

package fsnotify

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func FuzzInotify(f *testing.F) {
	f.Fuzz(func(t *testing.T, op1, op2, op3, op4, op5, op6, op7, op8,
		op9, op10, op11, op12, op13, op14, op15, op16 uint8,
		data1, data2, data3, data4, data5, data6,
		data7, data8 string) {
		ops := []int{int(op1), int(op2), int(op3), int(op4), int(op5),
			int(op6), int(op7), int(op8), int(op8), int(op8),
			int(op9), int(op10), int(op11), int(op12), int(op13),
			int(op14), int(op15), int(op16)}
		data := []string{data1, data2, data3, data4, data5, data6, data7, data8}

		opCounter := 0
		dataCounter := 0

		createdFiles := make([]string, 0)
		createdSubDirs := make([]string, 0)
		createdSubDirs = append(createdSubDirs, ".")

		tmp := t.TempDir()
		w := newCollector(t, tmp)
		w.collect(t)
		var sb strings.Builder
		var wantLogger strings.Builder

		for i := 0; i < 5; i++ {
			switch ops[opCounter] % 3 {
			case 0:
				// Create file
				t.Log("In case 0")
				filename, err := getSanitizedName([]byte(data[dataCounter]))
				dataCounter += 1
				if err != nil {
					continue
				}
				parentDir := createdSubDirs[ops[opCounter]%len(createdSubDirs)]
				opCounter += 1
				filename = filepath.Join(parentDir, filename)

				t.Log("checking if exists...")
				fi, err := os.Stat(filepath.Join(filepath.Join(tmp, filename)))
				switch {
				case errors.Is(err, os.ErrNotExist):
					sb.WriteString(fmt.Sprintf("CREATE    /%s\n", filename))
					t.Logf("touching file: %s", filename)
				case fi.Mode().IsDir():
					continue
				case err == nil:
					sb.WriteString(fmt.Sprintf("WRITE    /%s\n", filename))
					t.Logf("touch/writing file: %s", filename)
				}
				t.Log("done checking if exists")

				fuzzTouch(t, tmp, filename)
				if !slices.Contains(createdFiles, filename) {
					createdFiles = append(createdFiles, filename)
				}
			case 1:
				// Create and write file
				t.Log("In case 1")
				filename, err := getSanitizedName([]byte(data[dataCounter]))
				dataCounter += 1
				if err != nil {
					continue
				}
				t.Log("____have name")
				parentDir := createdSubDirs[ops[opCounter]%len(createdSubDirs)]
				opCounter += 1
				filename = filepath.Join(parentDir, filename)
				fileContents := data[dataCounter]
				dataCounter += 1
				var fileExists bool
				if fi, err := os.Stat(filepath.Join(filepath.Join(tmp, filename))); errors.Is(err, os.ErrNotExist) {
					fileExists = false
				} else if fi.Mode().IsDir() {
					continue
				} else {
					fileExists = true
				}
				if !slices.Contains(createdFiles, filename) {
					createdFiles = append(createdFiles, filename)
				}
				t.Logf("len of file contents: %d", len(fileContents))
				echoAppend(t, fileContents, tmp, filename)
				if !fileExists {
					sb.WriteString(fmt.Sprintf("CREATE    /%s\n", filename))
					t.Logf("CREATE'ing %s", filename)
				}
				if len(fileContents) != 0 {
					t.Logf("Writing %s", filename)
					sb.WriteString(fmt.Sprintf("WRITE    /%s\n", filename))
					t.Logf("echo appending file: %s", filename)
				}
			case 2:
				// Create subdir in the watched dir
				t.Log("In case 2")
				subDirName, err := getSanitizedName([]byte(data[dataCounter]))
				dataCounter += 1
				if err != nil {
					continue
				}
				t.Log("____have name")

				// Select a parent dir to create the new subdir in
				opCounter += 1
				parentDir := createdSubDirs[ops[opCounter]%len(createdSubDirs)]
				if _, err := os.Stat(filepath.Join(filepath.Join(tmp, parentDir, subDirName))); errors.Is(err, os.ErrNotExist) {
					createdSubDirs = append(createdSubDirs, filepath.Join(parentDir, subDirName))
					t.Logf("Creating subdir: %s", filepath.Join(parentDir, subDirName))
					mkdir(t, tmp, parentDir, subDirName)
					sb.WriteString(fmt.Sprintf("CREATE    /%s\n", filepath.Join(parentDir, subDirName)))
					if err := w.w.Add(filepath.Join(tmp, parentDir, subDirName)); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
		evs := w.stop(t)
		s := sb.String()
		fmt.Println(wantLogger.String())
		cmpEvents(t, tmp, evs, newEvents(t, s))
		return
	})
}

func getSanitizedName(data []byte) (string, error) {
	b64Name := base64.URLEncoding.EncodeToString(data)
	nameWoSlashes := strings.Replace(b64Name, "/", "", -1)
	if len(nameWoSlashes) == 0 {
		return "", errors.New("Too short name")
	}
	sanitizedName := filepath.Clean(nameWoSlashes)
	if len(sanitizedName) > 60 {
		sanitizedName = sanitizedName[:60]
	}
	return sanitizedName, nil
}

// touch but without fatal'ing if it could not create the file
// error means that the touch did not create a file
func fuzzTouch(t *testing.T, path ...string) error {
	t.Helper()
	if len(path) < 1 {
		t.Fatalf("touch: path must have at least one element: %s", path)
	}
	fp, err := os.Create(join(path...))
	if err != nil {
		return err
	}
	err = fp.Close()
	if err != nil {
		t.Fatalf("touch(%q): %s", join(path...), err)
	}
	if shouldWait(path...) {
		eventSeparator()
	}
	return nil
}
