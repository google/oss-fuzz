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
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

func ExecBuildCommand(bin string, args []string) (int, string, string) {
	// Executes the original command.
	cmd := exec.Command(bin, args...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	cmd.Stdin = os.Stdin
	cmd.Run()
	return cmd.ProcessState.ExitCode(), outb.String(), errb.String()
}

func Compile(bin string, args []string) (int, string, string) {
	// Run the actual command.
	return ExecBuildCommand(bin, args)
}

func AppendStringToFile(filepath, new_content string) error {
	// Appends |new_content| to the content of |filepath|.
	file, err := os.OpenFile(filepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(new_content)
	return err
}

func WriteStdErrOut(args []string, outstr string, errstr string) {
	// Prints |outstr| to stdout, prints |errstr| to stderr, and saves |errstr| to err.log.
	fmt.Print(outstr)
	fmt.Fprint(os.Stderr, errstr)
	// Record what compile args produced the error and the error itself in log file.
	AppendStringToFile("/tmp/err.log", fmt.Sprintf("%s\n", args)+errstr)
}

func main() {
	f, err := os.OpenFile("/tmp/jcc.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%s\n", os.Args)); err != nil {
		log.Println(err)
	}

	args := os.Args[1:]
	basename := filepath.Base(os.Args[0])
	isCPP := basename == "clang++-jcc"
	newArgs := args

	var bin string
	if isCPP {
		bin = "clang++"
	} else {
		bin = "clang"
	}
	fullCmdArgs := append([]string{bin}, newArgs...)
	retcode, out, errstr := Compile(bin, newArgs)
	WriteStdErrOut(fullCmdArgs, out, errstr)
	os.Exit(retcode)
}
