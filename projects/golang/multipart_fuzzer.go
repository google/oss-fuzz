// Copyright 2015 go-fuzz project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package multipart

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/textproto"
	"runtime"

	"github.com/dvyukov/go-fuzz-corpus/fuzz"
)

type Part struct {
	hdr  textproto.MIMEHeader
	data []byte
}

func Fuzz(data []byte) int {
	defer func() {
		if r := recover(); r != nil {
		}
		runtime.GC()
	}()
	const boundary = "dfhjksd23f43242f43fv4b4g2g2g23vf2"
	{
		r := multipart.NewReader(bytes.NewReader(data), boundary)
		f, err := r.ReadForm(1 << 20)
		if err == nil {
			f.RemoveAll()
		}
	}
	fmt.Println("Creating multipart reader")
	r := multipart.NewReader(bytes.NewReader(data), boundary)
	fmt.Println("Reading")
	var parts []Part
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0
		}
		p.FileName()
		p.FormName()
		pdata, err := ioutil.ReadAll(p)
		if err != nil {
			return 0
		}
		p.Close()
		// The parser is loose here.
		// If data contains \n followed by boundary (but without \r),
		// it parses it as part body. However, when it serializes it back,
		// it writes \r\n followed by boundary, which becomes new part separator.
		if bytes.Contains(pdata, []byte(boundary)) {
			continue
		}
		parts = append(parts, Part{p.Header, pdata})
	}
	if len(parts) == 0 {
		return 0
	}

	fmt.Println("Creating new writer")
	buf := new(bytes.Buffer)
	w := multipart.NewWriter(buf)
	w.SetBoundary(boundary)
	fmt.Println("Writing data")
	for _, p := range parts {
		pw, err := w.CreatePart(p.hdr)
		if err != nil {
			panic(err)
		}
		n, err := pw.Write(p.data)
		if err != nil {
			panic(err)
		}
		if n != len(p.data) {
			panic("partial write")
		}
	}
	w.Close()

	fmt.Println("Time to compare")
	data1 := buf.Bytes()
	r1 := multipart.NewReader(buf, boundary)
	var parts1 []Part
	for {
		p, err := r1.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Printf("parts0: %+v\n", parts)
			fmt.Printf("data0: %q\n", data)
			fmt.Printf("data1: %q\n", data1)
			panic(err)
		}
		p.FileName()
		p.FormName()
		pdata, err := ioutil.ReadAll(p)
		if err != nil {
			panic(err)
		}
		p.Close()
		parts1 = append(parts1, Part{p.Header, pdata})
	}

	fmt.Println("Performing deep equal")

	if !fuzz.DeepEqual(parts, parts1) {
		fmt.Printf("parts0: %+v\n", parts)
		fmt.Printf("parts1: %+v\n", parts1)
		fmt.Printf("data0: %q\n", data)
		fmt.Printf("data1: %q\n", data1)
		panic("data has changed")
	}
	return 1
}
