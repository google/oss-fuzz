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
	"slices"
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

	retcode, out, err := Compile("clang++", newCmdline)
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

	_, _, stderr := Compile(bin, cmd)
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

func EnsureDir(dirPath string) {
	// Checks if a path is an existing directory, otherwise create one.
	if pathInfo, err := os.Stat(dirPath); err == nil {
		if isDir := pathInfo.IsDir(); !isDir {
			panic(dirPath + " exists but is not a directory.")
		}
	} else if errors.Is(err, fs.ErrNotExist) {
		if err := os.MkdirAll(dirPath, 0755); err != nil {
			panic("Failed to create directory: " + dirPath + ".")
		}
		fmt.Println("Created directory: " + dirPath + ".")
	} else {
		panic("An error occurred in os.Stat(" + dirPath + "): " + err.Error())
	}
}

func GenerateAST(bin string, args []string, filePath string) {
	// Generates AST.
	outFile, err := os.Create(filePath)
	if err != nil {
		fmt.Println(err)
	}
	defer outFile.Close()

	cmd := exec.Command(bin, args...)
	cmd.Stdout = outFile
	cmd.Run()
}

func GenerateASTs(bin string, args []string, astDir string) {
	// Generates an AST for each C/CPP file in the command.
	// Cannot save AST when astDir is not available.
	EnsureDir(astDir)

	// Target file suffixes.
	suffixes := []string{".cpp", ".cc", ".cxx", ".c++", ".c", ".h", ".hpp"}
	// C/CPP targets in the command.
	targetFiles := []string{}
	// Flags to generate AST.
	flags := []string{"-Xclang", "-ast-dump=json", "-fsyntax-only"}
	for _, arg := range args {
		targetFileExt := strings.ToLower(filepath.Ext(arg))
		if slices.Contains(suffixes, targetFileExt) {
			targetFiles = append(targetFiles, arg)
			continue
		}
		flags = append(flags, arg)
	}

	// Generate an AST for each target file. Skips AST generation when a
	// command has no target file (e.g., during linking).
	for _, targetFile := range targetFiles {
		filePath := filepath.Join(astDir, fmt.Sprintf("%s.ast", filepath.Base(targetFile)))
		GenerateAST(bin, append(flags, targetFile), filePath)
	}
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
	// Generate ASTs f we define this ENV var.
	if astDir := os.Getenv("JCC_GENERATE_AST_DIR"); astDir != "" {
		GenerateASTs(bin, args, astDir)
	}
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

func WriteStdErrOut(outstr string, errstr string) {
	// Prints |outstr| to stdout, prints |errstr| to stderr, and saves |errstr| to err.log.
	fmt.Print(outstr)
	fmt.Fprint(os.Stderr, errstr)
	AppendStringToFile("/out/err.log", errstr)
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
	newArgs := []string{"-w", "-stdlib=libc++"}
	newArgs = append(args, newArgs...)

	var bin string
	if isCPP {
		bin = "clang++"
		// TODO: Should `-stdlib=libc++` be added only here?
	} else {
		bin = "clang"
	}
	retcode, out, errstr := Compile(bin, newArgs)
	if retcode == 0 {
		WriteStdErrOut(out, errstr)
		os.Exit(0)
	}

	// Note that on failures or when we succeed on the first try, we should
	// try to write the first out/err to stdout/stderr.
	// When we fail we should try to write the original out/err and one from
	// the corrected.

	headersFixed, _ := CorrectMissingHeaders(bin, newArgs)
	if headersFixed {
		// We succeeded here but it's kind of complicated to get out and
		// err from TryCompileAndFixHeadersOnce. The output and err is
		// not so important on success so just be silent.
		os.Exit(0)
	}

	if isCPP {
		// Nothing else we can do. Just write the error and exit.
		// Just print the original error for debugging purposes and
		//  to make build systems happy.
		WriteStdErrOut(out, errstr)
		os.Exit(retcode)
	}
	fixret, fixout, fixerr := TryFixCCompilation(newArgs)
	if fixret != 0 {
		// We failed, write stdout and stderr from the first failure and
		// from fix failures so we can know what the code did wrong and
		// how to improve jcc to fix more issues.
		WriteStdErrOut(out, errstr)
		fmt.Println("\nFix failure")
		// Print error back to stderr so tooling that relies on this can proceed
		WriteStdErrOut(fixout, fixerr)
		os.Exit(retcode)
	}
	// The fix suceeded, write its out and err.
	WriteStdErrOut(fixout, fixerr)
}
