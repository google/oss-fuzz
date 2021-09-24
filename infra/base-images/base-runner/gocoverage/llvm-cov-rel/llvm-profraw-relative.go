package main

import (
	"debug/elf"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
)

type ProfrawHeaderVersion7 struct {
	ProfrawHeaderGeneric
	BinaryIdsSize              uint64
	DataSize                   uint64
	PaddingBytesBeforeCounters uint64
	CountersSize               uint64
	PaddingBytesAfterCounters  uint64
	NamesSize                  uint64
	CountersDelta              uint64
	NamesDelta                 uint64
	ValueKindLast              uint64
}

type ProfrawHeaderGeneric struct {
	Magic   uint64
	Version uint64
}

type ProfrawData struct {
	NameRef         uint64
	FuncHash        uint64
	CounterPtr      uint64
	FunctionPointer uint64
	Values          uint64
	NumCounters     uint32
	NumValueSites   []uint16
}

const PROFRAW_HEADER_GENERIC_LEN = 16
const PROFRAW_HEADER_7_LEN = 88

func parseProfrawHeaderGeneric(data []byte) (ProfrawHeaderGeneric, error) {
	r := ProfrawHeaderGeneric{}
	if len(data) < PROFRAW_HEADER_GENERIC_LEN {
		return r, io.EOF
	}
	r.Magic = binary.LittleEndian.Uint64(data[:8])
	r.Version = binary.LittleEndian.Uint64(data[8:16])
	if r.Magic != 0xff6c70726f667281 {
		return r, fmt.Errorf("Invalid magic %x", r.Magic)
	}
	return r, nil
}

func relativizeAddress(data []byte, offset int, databegin uint64, sectPrfCnts uint64, sectPrfData uint64) {
	value := binary.LittleEndian.Uint64(data[offset : offset+8])
	if value >= sectPrfCnts && value < sectPrfData {
		// If the value is an address in the right section,
		// Make it relative.
		value = value - databegin
		binary.LittleEndian.PutUint64(data[offset:offset+8], value)
	}

}

func profrawDataLen(ipvklast uint64) int {
	return 44 + 2*(int(ipvklast)+1)
}

func relativizeProfraw(data []byte, sectPrfCnts uint64, sectPrfData uint64) (error, []byte) {
	h := ProfrawHeaderVersion7{}
	var err error
	h.ProfrawHeaderGeneric, err = parseProfrawHeaderGeneric(data)
	if err != nil {
		return err, data
	}
	if h.Version == 5 {
		// Upgrade from 5 to 7 by adding a zero binaryids in the header.
		binary.LittleEndian.PutUint64(data[8:16], 7)
		h.Version = 7
		data2 := make([]byte, len(data)+8)
		copy(data2, data[0:16])
		copy(data2[24:], data[16:])
		data = data2
	}
	if h.Version < 7 {
		return fmt.Errorf("Invalid version for profraw file: %v", h.Version), data
	}
	// At one point clang-14 will update to 8, and more work will be needed.
	if len(data) < PROFRAW_HEADER_7_LEN {
		return io.EOF, data
	}
	h.BinaryIdsSize = binary.LittleEndian.Uint64(data[16:24])
	h.DataSize = binary.LittleEndian.Uint64(data[24:32])
	h.PaddingBytesBeforeCounters = binary.LittleEndian.Uint64(data[32:40])
	h.CountersSize = binary.LittleEndian.Uint64(data[40:48])
	h.PaddingBytesAfterCounters = binary.LittleEndian.Uint64(data[48:56])
	h.NamesSize = binary.LittleEndian.Uint64(data[56:64])
	h.CountersDelta = binary.LittleEndian.Uint64(data[64:72])
	h.NamesDelta = binary.LittleEndian.Uint64(data[72:80])
	h.ValueKindLast = binary.LittleEndian.Uint64(data[80:88])

	if h.CountersDelta != sectPrfCnts-sectPrfData {
		// Rust linking adds an offset ? not seen in readelf.
		sectPrfData = h.CountersDelta - sectPrfCnts + sectPrfData
		sectPrfCnts = h.CountersDelta
	}
	dataref := sectPrfData
	relativizeAddress(data, 64, dataref, sectPrfCnts, sectPrfData)

	offset := PROFRAW_HEADER_7_LEN + int(h.BinaryIdsSize)
	for i := uint64(0); i < h.DataSize; i++ {
		if len(data) < offset+profrawDataLen(h.ValueKindLast) {
			return io.EOF, data
		}
		d := ProfrawData{}
		d.NameRef = binary.LittleEndian.Uint64(data[offset : offset+8])
		d.FuncHash = binary.LittleEndian.Uint64(data[offset+8 : offset+16])
		d.CounterPtr = binary.LittleEndian.Uint64(data[offset+16 : offset+24])
		d.FunctionPointer = binary.LittleEndian.Uint64(data[offset+24 : offset+32])
		d.Values = binary.LittleEndian.Uint64(data[offset+32 : offset+40])
		d.NumCounters = binary.LittleEndian.Uint32(data[offset+40 : offset+44])
		d.NumValueSites = make([]uint16, h.ValueKindLast+1)
		for j := 0; j <= int(h.ValueKindLast); j++ {
			d.NumValueSites[j] = binary.LittleEndian.Uint16(data[offset+44+2*j : offset+46+2*j])
		}

		relativizeAddress(data, offset+16, dataref, sectPrfCnts, sectPrfData)
		// We need this because of CountersDelta -= sizeof(*SrcData); in __llvm_profile_merge_from_buffer.
		dataref += uint64(profrawDataLen(h.ValueKindLast))

		offset += profrawDataLen(h.ValueKindLast)
	}
	return nil, data
}

func main() {
	flag.Parse()

	if len(flag.Args()) != 3 {
		log.Fatalf("needs exactly three arguments : binary, profraw, output")
	}

	// First find llvm profile sections addresses in the elf.
	f, err := elf.Open(flag.Args()[0])
	if err != nil {
		log.Fatalf("failed to read elf: %v", err)
	}
	sectPrfCnts := uint64(0)
	sectPrfData := uint64(0)
	for i := range f.Sections {
		if f.Sections[i].Name == "__llvm_prf_cnts" {
			sectPrfCnts = f.Sections[i].Addr
		} else if f.Sections[i].Name == "__llvm_prf_data" {
			sectPrfData = f.Sections[i].Addr
			// Maybe rather sectPrfCntsEnd as f.Sections[i].Addr + f.Sections[i].Size for __llvm_prf_cnts.
		}
	}
	if sectPrfCnts == 0 || sectPrfData == 0 {
		log.Fatalf("Elf has not __llvm_prf_cnts and __llvm_prf_data sections")
	}

	// Process profraw file.
	data, err := ioutil.ReadFile(flag.Args()[1])
	if err != nil {
		log.Fatalf("failed to read file: %v", err)
	}
	err, data = relativizeProfraw(data, sectPrfCnts, sectPrfData)
	if err != nil {
		log.Fatalf("failed to process file: %v", err)
	}

	// Write output file.
	err = ioutil.WriteFile(flag.Args()[2], data, 0644)
	if err != nil {
		log.Fatalf("failed to write file: %v", err)
	}
}
