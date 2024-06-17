// Copyright 2024 Google LLC
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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var MaxMissingHeaderFiles = 10
var CppifyHeadersMagicString = "\n/* JCCCppifyHeadersMagicString */\n"

func CopyFile(src string, dst string) {
	contents, err := ioutil.ReadFile(src)
	if err != nil {
		panic(err)
	}
	err = ioutil.WriteFile(dst, contents, 0644)
	if err != nil {
		panic(err)
	}
}

func TryFixCCompilation(cmdline []string) ([]string, int, string, string) {
	var newFile string = ""
	for i, arg := range cmdline {
		if !strings.HasSuffix(arg, ".c") {
			continue
		}
		if _, err := os.Stat(arg); errors.Is(err, os.ErrNotExist) {
			continue
		}
		newFile = strings.TrimSuffix(arg, ".c")
		newFile += ".cpp"
		CopyFile(arg, newFile)
		CppifyHeaderIncludesFromFile(newFile)
		cmdline[i] = newFile
		break
	}
	if newFile == "" {
		return []string{}, 1, "", ""
	}
	cppBin := "clang++"
	newCmdline := []string{"-stdlib=libc++"}
	newCmdline = append(cmdline, newCmdline...)
	newFullArgs := append([]string{cppBin}, newCmdline...)

	retcode, out, err := Compile(cppBin, newCmdline)
	if retcode == 0 {
		return newFullArgs, retcode, out, err
	}
	correctedCmdline, corrected, _ := CorrectMissingHeaders(cppBin, newCmdline)
	if corrected {
		return append([]string{cppBin}, correctedCmdline...), 0, "", ""
	}
	return newFullArgs, retcode, out, err
}

func ExtractMissingHeader(compilerOutput string) (string, bool) {
	r := regexp.MustCompile(`fatal error: ['|<](?P<header>[a-zA-z0-9\/\.]+)['|>] file not found`)
	matches := r.FindStringSubmatch(compilerOutput)
	if len(matches) == 0 {
		return "", false
	}
	return matches[1], true
}

func ReplaceMissingHeaderInFile(srcFilename, curHeader, replacementHeader string) error {
	srcFile, err := os.Open(srcFilename)
	if err != nil {
		return err
	}
	srcBytes, err := ioutil.ReadAll(srcFile)
	if err != nil {
		return err
	}
	src := string(srcBytes)
	newSrc := ReplaceMissingHeader(src, curHeader, replacementHeader)
	b := []byte(newSrc)
	err = ioutil.WriteFile(srcFilename, b, 0644)
	if err != nil {
		return err
	}
	return nil
}

func ReplaceMissingHeader(src, curHeader, replacementHeader string) string {
	re := regexp.MustCompile(`#include ["|<]` + curHeader + `["|>]\n`)
	replacement := "#include \"" + replacementHeader + "\"\n"
	return re.ReplaceAllString(src, replacement)
}

func GetHeaderCorrectedFilename(compilerErr string) (string, string, bool) {
	re := regexp.MustCompile(`(?P<buggy>[a-z\/\-\_0-9A-z\.]+):.* fatal error: .* file not found`)
	matches := re.FindStringSubmatch(compilerErr)
	if len(matches) < 2 {
		return "", "", false
	}
	oldFilename := matches[1]
	base := filepath.Base(oldFilename)
	root := filepath.Dir(oldFilename)
	newFilename := root + "/jcc-corrected-" + base
	return oldFilename, newFilename, true
}

func GetHeaderCorrectedCmd(cmd []string, compilerErr string) ([]string, string, error) {
	oldFilename, newFilename, success := GetHeaderCorrectedFilename(compilerErr)
	if !success {
		return cmd, "", errors.New("Couldn't find buggy file")
	}
	// Make new cmd.
	newCmd := make([]string, len(cmd))
	for i, part := range cmd {
		newCmd[i] = part
	}
	found := false
	for i, filename := range newCmd {
		if filename == oldFilename {
			newCmd[i] = newFilename
			found = true
			break
		}
	}
	CopyFile(oldFilename, newFilename)
	if found {
		return newCmd, newFilename, nil
	}
	return cmd, "", errors.New("Couldn't find file")
}

func CorrectMissingHeaders(bin string, cmd []string) ([]string, bool, error) {

	_, _, stderr := Compile(bin, cmd)
	cmd, correctedFilename, err := GetHeaderCorrectedCmd(cmd, stderr)
	if err != nil {
		return cmd, false, err
	}
	for i := 0; i < MaxMissingHeaderFiles; i++ {
		fixed, hasBrokenHeaders := TryCompileAndFixHeadersOnce(bin, cmd, correctedFilename)
		if fixed {
			return cmd, true, nil
		}
		if !hasBrokenHeaders {
			return cmd, false, nil
		}
	}
	return cmd, false, nil
}

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

func TryCompileAndFixHeadersOnce(bin string, cmd []string, filename string) (fixed, hasBrokenHeaders bool) {
	retcode, _, err := Compile(bin, cmd)
	if retcode == 0 {
		fixed = true
		hasBrokenHeaders = false
		return
	}
	missingHeader, isMissing := ExtractMissingHeader(err)
	if !isMissing {
		fixed = false
		hasBrokenHeaders = false
		return
	}

	newHeaderPath, found := FindMissingHeader(missingHeader)
	if !found {
		fixed = false
		hasBrokenHeaders = true
		return false, true
	}
	ReplaceMissingHeaderInFile(filename, missingHeader, newHeaderPath)
	return false, true
}

func FindMissingHeader(missingHeader string) (string, bool) {
	envVar := "JCC_MISSING_HEADER_SEARCH_PATH"
	var searchPath string
	searchPath, exists := os.LookupEnv(envVar)
	if !exists {
		searchPath = "/src"
	}
	searchPath, _ = filepath.Abs(searchPath)
	var headerLocation string
	missingHeader = "/" + missingHeader
	find := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(path, missingHeader) {
			headerLocation = path
			return nil
		}
		return nil
	}
	filepath.WalkDir(searchPath, find)
	if headerLocation == "" {
		return "", false
	}
	return headerLocation, true
}

func CppifyHeaderIncludesFromFile(srcFile string) error {
	contentsBytes, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return err
	}
	contents := string(contentsBytes[:])
	contents, err = CppifyHeaderIncludes(contents)
	if err != nil {
		return err
	}
	b := []byte(contents)
	err = ioutil.WriteFile(srcFile, b, 0644)
	return err
}

func CppifyHeaderIncludes(contents string) (string, error) {
	shouldCppify, exists := os.LookupEnv("JCC_CPPIFY_PROJECT_HEADERS")
	if !exists || strings.Compare(shouldCppify, "0") == 0 {
		return contents, nil
	}
	if strings.Contains(contents, CppifyHeadersMagicString) {
		return contents, nil
	}
	re := regexp.MustCompile(`\#include \"(?P<header>.+)\"\n`)
	matches := re.FindAllStringSubmatch(contents, -1)
	if len(matches) == 0 {
		return "", nil // !!!
	}
	for i, match := range matches {
		if i == 0 {
			// So we don't cppify twice.
			contents += CppifyHeadersMagicString
		}
		oldStr := match[0]
		replacement := "extern \"C\" {\n#include \"" + match[1] + "\"\n}\n"
		contents = strings.Replace(contents, oldStr, replacement, 1)
		if strings.Compare(contents, "") == 0 {
			panic("Failed to replace")
		}
	}
	return contents, nil
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
	AppendStringToFile("/workspace/err.log", fmt.Sprintf("%s\n", args)+errstr)
}

func main() {
	f, err := os.OpenFile("/tmp/jcc.log", os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Println(err)
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%s\n", os.Args)); err != nil {
		log.Println(err)
	}

	args := os.Args[1:]
	if args[0] == "unfreeze" {
		fmt.Println("unfreeze")
		unfreeze()
	}
	basename := filepath.Base(os.Args[0])
	isCPP := basename == "clang++-jcc"
	newArgs := append(args, "-w")

	var bin string
	if isCPP {
		bin = "clang++"
		newArgs = append(args, "-stdlib=libc++")
	} else {
		bin = "clang"
	}
	fullCmdArgs := append([]string{bin}, newArgs...)
	if IsCompilingTarget(fullCmdArgs) {
		WriteTargetArgsAndCommitImage(fullCmdArgs)
		os.Exit(0)
	}
	retcode, out, errstr := Compile(bin, newArgs)
	WriteStdErrOut(fullCmdArgs, out, errstr)
	os.Exit(retcode)
}

type BuildCommand struct {
	CWD string   `json:"CWD"`
	CMD []string `json:"CMD"`
}

func WriteTargetArgsAndCommitImage(cmdline []string) {
	log.Println("WRITE COMMAND")
	f, _ := os.OpenFile("/out/statefile.json", os.O_CREATE|os.O_WRONLY, 0644)
	wd, _ := os.Getwd()
	buildcmd := BuildCommand{
		CWD: wd,
		CMD: cmdline,
	}
	jsonData, _ := json.Marshal(buildcmd)
	f.Write(jsonData)
	f.Close()
	hostname, _ := os.Hostname()
	dockerArgs := []string{"commit", hostname, "frozen"}
	cmd := exec.Command("docker", dockerArgs...)
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	cmd.Stdin = os.Stdin
	cmd.Run()
	fmt.Println(outb.String(), errb.String())
	fmt.Println("COMMIT IMAGE")
}

func IsCompilingTarget(cmdline []string) bool {
	for _, arg := range cmdline {
		// This can fail if people do crazy things they aren't supposed
		// to such as using some other means to link in libFuzzer.
		if arg == "-fsanitize=fuzzer" {
			return true
		}
		if arg == "-lFuzzingEngine" {
			return true
		}
	}
	return false
}

func parseCommand(command string) (string, []string) {
	args := strings.Fields(command)
	commandBin := args[0]
	commandArgs := args[1:]
	return commandBin, commandArgs
}

func unfreeze() {
	content, err := ioutil.ReadFile("/out/statefile.json")
	if err != nil {
		log.Fatal(err)
	}
	var command BuildCommand
	json.Unmarshal(content, &command)
	bin, args := parseCommand(strings.Join(command.CMD, " "))
	os.Chdir(command.CWD)
	ExecBuildCommand(bin, args)
	os.Exit(0)
}
