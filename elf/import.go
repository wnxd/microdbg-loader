package elf

import (
	"bytes"
	"debug/elf"
	"io"
	"io/fs"
	"math"
	"path/filepath"

	"github.com/wnxd/microdbg/debugger"
	"github.com/wnxd/microdbg/emulator"
)

func Import(dbg debugger.Debugger, path string, r io.ReaderAt) (Module, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	return importDynamic(dbg, filepath.Base(path), f)
}

func ImportPath(dbg debugger.Debugger, path string) (Module, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	return importDynamic(dbg, filepath.Base(path), f)
}

func ImportFile(dbg debugger.Debugger, file fs.File) (Module, error) {
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	r, ok := file.(io.ReaderAt)
	if !ok {
		var buf bytes.Buffer
		buf.ReadFrom(file)
		r = bytes.NewReader(buf.Bytes())
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	return importDynamic(dbg, info.Name(), f)
}

func importDynamic(dbg debugger.Debugger, name string, f *elf.File) (Module, error) {
	defer f.Close()
	emu := dbg.Emulator()
	if machineToArch(f.Machine) != emu.Arch() {
		return nil, emulator.ErrArchMismatch
	}
	var totalBegin uint64 = math.MaxUint64
	var totalEnd uint64 = 0
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if prog.Vaddr < totalBegin {
			totalBegin = prog.Vaddr
		}
		if end := prog.Vaddr + prog.Memsz; end > totalEnd {
			totalEnd = end
		}
	}
	region, err := dbg.MapAlloc(totalEnd-totalBegin, emulator.MEM_PROT_ALL)
	if err != nil {
		return nil, err
	}
	return importRegion(dbg, region, totalBegin, name, f)
}

func importRegion(dbg debugger.Debugger, region emulator.MemRegion, offset uint64, name string, f *elf.File) (Module, error) {
	emu := dbg.Emulator()
	progs := make([]elf.ProgHeader, len(f.Progs))
	for i, prog := range f.Progs {
		progs[i] = prog.ProgHeader
		if prog.Type != elf.PT_LOAD || prog.Filesz == 0 {
			continue
		}
		w := io.NewOffsetWriter(emulator.ToPointer(emu, region.Addr), int64(prog.Vaddr-offset))
		io.CopyN(w, prog.Open(), int64(prog.Filesz))
	}
	// regionEnd := region.Addr + region.Size
	// for i, section := range f.Sections {
	// if section.Flags&elf.SHF_WRITE == 0 {
	// 	continue
	// }
	// if section.Size == 0 || section.Addr < region.Addr || (section.Addr+section.Size) >= regionEnd {
	// 	continue
	// }
	// w := io.NewOffsetWriter(emulator.ToPointer(emu, region.Addr), int64(section.Addr-region.Addr))
	// io.CopyN(w, section.Open(), int64(section.Size))
	// }
	module := &module{
		name:   name,
		dbg:    dbg,
		region: region,
		header: f.FileHeader,
		progs:  progs,
	}
	module.init()
	return module, nil
}

func machineToArch(machine elf.Machine) emulator.Arch {
	switch machine {
	case elf.EM_ARM:
		return emulator.ARCH_ARM
	case elf.EM_AARCH64:
		return emulator.ARCH_ARM64
	case elf.EM_386:
		return emulator.ARCH_X86
	case elf.EM_X86_64:
		return emulator.ARCH_X86_64
	default:
		return emulator.ARCH_UNKNOWN
	}
}
