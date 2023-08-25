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
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
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

func TryFixCCompilation(cmdline []string) (int, string, string) {
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
		return 1, "", ""
	}
	newCmdline := []string{"-stdlib=libc++"}
	newCmdline = append(cmdline, newCmdline...)

	retcode, out, err := compile("clang++", newCmdline)
	if retcode == 0 {
		return retcode, out, err
	}
	corrected, _ := CorrectMissingHeaders("clang++", newCmdline)
	if corrected {
		return 0, "", ""
	}
	return retcode, out, err
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

func CorrectMissingHeaders(bin string, cmd []string) (bool, error) {

	_, _, stderr := compile(bin, cmd)
	cmd, correctedFilename, err := GetHeaderCorrectedCmd(cmd, stderr)
	if err != nil {
		return false, err
	}
	for i := 0; i < MaxMissingHeaderFiles; i++ {
		fixed, hasBrokenHeaders := TryCompileAndFixHeadersOnce(bin, cmd, correctedFilename)
		if fixed {
			return true, nil
		}
		if !hasBrokenHeaders {
			return false, nil
		}
	}
	return false, nil
}

func RunCommand(cmd *exec.Cmd) (int, string, string) {
	// Executes a command and returns the output.
	var outb, errb bytes.Buffer
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	cmd.Run()
	return cmd.ProcessState.ExitCode(), outb.String(), errb.String()
}

func ExecOriginalCommand(bin string, args []string) (int, string, string) {
	// Executes the original command.
	cmd := exec.Command(bin, args...)
	return RunCommand(cmd)
}

func Contains(slice []string, item string) bool {
	// Checks if the slice contains item.
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func FindTargetFile(args []string) string {
	// Finds the fuzz target file by file extension.
	suffixes := []string{".cpp", ".cc", ".cxx", ".c++", ".c"}
	for _, arg := range args {
		if Contains(suffixes, filepath.Ext(arg)) {
			return filepath.Base(arg)
		}
	}
	// Uses a time stamp as AST filename if no target file is found.
	return time.Now().Format("20060102_150405.000")
}

func RemoveIfEmpty(filepath string) {
	// Removes filepath if it is empty.
	info, _ := os.Stat(filepath)
	if info.Size() == 0 { os.Remove(filepath) }
}

func GenerateAST(bin string, args []string) (int, string, string) {
	// Generates AST.
	newArgs := append(args, "-Xclang", "-ast-dump=json", "-fsyntax-only")

	targetFile := FindTargetFile(args)
	filePath := filepath.Join("/tmp", fmt.Sprintf("%s.txt", targetFile))

	cmdStr := fmt.Sprintf("%s %s > %s", bin, strings.Join(newArgs, " "), filePath)
	cmd := exec.Command("sh", "-c", cmdStr)
	retCode, stdout, stderr := RunCommand(cmd)

	RemoveIfEmpty(filePath)
	return retCode, stdout, stderr
}

func compile(bin string, args []string) (int, string, string) {
	// Generate AST.
	retCode, stdout, stderr := GenerateAST(bin, args)
	// Run the actual command.
	retCode, stdout, stderr = ExecOriginalCommand(bin, args)
	return retCode, stdout, stderr
}

func TryCompileAndFixHeadersOnce(bin string, cmd []string, filename string) (fixed, hasBrokenHeaders bool) {
	retcode, _, err := compile(bin, cmd)
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

func main() {
	f, err2 := os.OpenFile("/tmp/jcc.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err2 != nil {
		log.Println(err2)
	}
	defer f.Close()
	if _, err2 := f.WriteString(fmt.Sprintf("%s\no", os.Args)); err2 != nil {
		log.Println(err2)
	}

	args := os.Args[1:]
	basename := filepath.Base(os.Args[0])
	isCPP := basename == "clang++-jcc"
	newArgs := []string{"-w", "-stdlib=libc++"}
	newArgs = append(args, newArgs...)
	var retcode int
	var out string
	var err string
	var bin string
	if isCPP {
		bin = "clang++"
		retcode, out, err = compile(bin, newArgs)
	} else {
		bin = "clang"
		retcode, out, err = compile(bin, newArgs)
	}
	if retcode == 0 {
		fmt.Println(out)
		fmt.Println(err)
		os.Exit(0)
	}

	headersFixed, _ := CorrectMissingHeaders(bin, newArgs)
	if headersFixed {
		os.Exit(0)
	}

	if isCPP {
		// Nothing else we can do. Just print the error and exit.
		fmt.Println(out)
		fmt.Println(err)
		os.Exit(retcode)
	}
	fixret, fixout, fixerr := TryFixCCompilation(newArgs)
	if fixret != 0 {
		fmt.Println(out)
		fmt.Println(err)
		fmt.Println("Fix failure")
		fmt.Println(fixout)
		fmt.Println(fixerr)
		os.Exit(retcode)
	}
}
