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
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func copy_file(src string, dst string) {
	contents, err := ioutil.ReadFile(src)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(dst, contents, 0644)
	if err != nil {
		panic(err)
	}
}

func fix_c_compilation(cmdline []string) bool {
	var new_file string = ""
	for i, arg := range cmdline {
		if !strings.HasSuffix(arg, ".c") {
			continue
		}
		if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
			continue
		}
		new_file = strings.TrimSuffix(arg, ".c")
		new_file += ".cpp"
		copy_file(arg, new_file)
		cmdline[i] = new_file
		break
	}
	if new_file == "" {
		return false
	}
	cmd := exec.Command("clang++", cmdline...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	fmt.Println(cmd)
	err := cmd.Run()
	fmt.Println(outb.String())
	fmt.Println(errb.String())
	if err != nil {
		return false
	}
	return true
}

func main() {
	args := os.Args[1:]
	basename := filepath.Base(os.Args[0])
	is_cpp := (basename == "clang++")
	new_args := []string{"-w"}
	new_args = append(args, new_args...)
	var cmd *exec.Cmd
	if is_cpp {
		cmd = exec.Command("clang++", new_args...)
	} else {
		cmd = exec.Command("clang", new_args...)
	}
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err := cmd.Run()
	if (err != nil) && !is_cpp {
		if !fix_c_compilation(new_args) {
			fmt.Println(outb.String())
			fmt.Println(errb.String())
			os.Exit(5)
		}
	}
}
