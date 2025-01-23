package elf

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"slices"
	"sync"
	"unsafe"

	"github.com/wnxd/microdbg/debugger"
	"github.com/wnxd/microdbg/emulator"
)

const (
	relType_Value = iota
	relType_Import
	relType_Addend = iota
	relType_Resolver
)

type Module interface {
	debugger.Module
	Symbols(yield func(debugger.Symbol) bool)
	Class() elf.Class
	DynValue(tag elf.DynTag) []uint64
	Needed() []string
	GetSymbol(index uint32) *elf.Symbol
	Reloc(rel any)
}

var (
	relInfoMap = map[elf.Machine]map[uint32]uint32{
		elf.EM_ARM: {
			uint32(elf.R_ARM_ABS32):     elf.R_INFO32(4, relType_Value),
			uint32(elf.R_ARM_RELATIVE):  elf.R_INFO32(4, relType_Addend),
			uint32(elf.R_ARM_GLOB_DAT):  elf.R_INFO32(4, relType_Import),
			uint32(elf.R_ARM_JUMP_SLOT): elf.R_INFO32(4, relType_Import),
			uint32(elf.R_ARM_IRELATIVE): elf.R_INFO32(4, relType_Resolver),
		},
		elf.EM_AARCH64: {
			uint32(elf.R_AARCH64_ABS64):     elf.R_INFO32(8, relType_Value),
			uint32(elf.R_AARCH64_ABS32):     elf.R_INFO32(4, relType_Value),
			uint32(elf.R_AARCH64_RELATIVE):  elf.R_INFO32(8, relType_Addend),
			uint32(elf.R_AARCH64_GLOB_DAT):  elf.R_INFO32(8, relType_Import),
			uint32(elf.R_AARCH64_JUMP_SLOT): elf.R_INFO32(8, relType_Import),
			uint32(elf.R_AARCH64_IRELATIVE): elf.R_INFO32(8, relType_Resolver),
		},
		elf.EM_386: {
			uint32(elf.R_386_32):        elf.R_INFO32(4, relType_Value),
			uint32(elf.R_386_RELATIVE):  elf.R_INFO32(4, relType_Addend),
			uint32(elf.R_386_GLOB_DAT):  elf.R_INFO32(4, relType_Import),
			uint32(elf.R_386_JMP_SLOT):  elf.R_INFO32(4, relType_Import),
			uint32(elf.R_386_IRELATIVE): elf.R_INFO32(4, relType_Resolver),
		},
		elf.EM_X86_64: {
			uint32(elf.R_X86_64_64):        elf.R_INFO32(8, relType_Value),
			uint32(elf.R_X86_64_32):        elf.R_INFO32(4, relType_Value),
			uint32(elf.R_X86_64_RELATIVE):  elf.R_INFO32(8, relType_Addend),
			uint32(elf.R_X86_64_GLOB_DAT):  elf.R_INFO32(8, relType_Import),
			uint32(elf.R_X86_64_JMP_SLOT):  elf.R_INFO32(8, relType_Import),
			uint32(elf.R_X86_64_IRELATIVE): elf.R_INFO32(8, relType_Resolver),
		},
	}
)

type module struct {
	name    string
	dbg     debugger.Debugger
	region  emulator.MemRegion
	header  elf.FileHeader
	progs   []elf.ProgHeader
	dynamic map[elf.DynTag][]uint64
	hash    elfHashTable
	gnuHash gnuHashTable
	needed  []string
	symbols []*elf.Symbol
	mu      sync.Mutex
	rels    []debugger.ControlHandler
	ifunc   sync.Map
}

func (m *module) init() {
	m.dynamic = make(map[elf.DynTag][]uint64)
	m.parseDynamic()
	m.parseHash()
	m.parseName()
	m.parseNeeded()
}

func (m *module) Close() error {
	for _, v := range m.rels {
		v.Close()
	}
	return m.dbg.MapFree(m.region.Addr, m.region.Size)
}

func (m *module) Name() string {
	return m.name
}

func (m *module) Region() (uint64, uint64) {
	return m.region.Addr, m.region.Size
}

func (m *module) BaseAddr() uint64 {
	return m.region.Addr
}

func (m *module) EntryAddr() uint64 {
	return m.BaseAddr() + m.header.Entry
}

func (m *module) Init(ctx context.Context) error {
	m.relocation()
	var initArray []uint64
	sz := m.dynamic[elf.DT_PREINIT_ARRAYSZ]
	for i, v := range m.dynamic[elf.DT_PREINIT_ARRAY] {
		sr := m.sectionReader(v, sz[i])
		switch m.header.Class {
		case elf.ELFCLASS32:
			initArray = append(initArray, m.parseArray32(sr)...)
		case elf.ELFCLASS64:
			initArray = append(initArray, m.parseArray64(sr)...)
		}
	}
	for _, v := range m.dynamic[elf.DT_INIT] {
		initArray = append(initArray, m.BaseAddr()+v)
	}
	sz = m.dynamic[elf.DT_INIT_ARRAYSZ]
	for i, v := range m.dynamic[elf.DT_INIT_ARRAY] {
		sr := m.sectionReader(v, sz[i])
		switch m.header.Class {
		case elf.ELFCLASS32:
			initArray = append(initArray, m.parseArray32(sr)...)
		case elf.ELFCLASS64:
			initArray = append(initArray, m.parseArray64(sr)...)
		}
	}
	for _, addr := range initArray {
		if addr == 0 {
			continue
		}
		err := m.call(ctx, addr)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *module) FindSymbol(name string) (uint64, error) {
	if sym, err := m.findGNUHashSymbol(name); sym != nil {
		return m.resolveSymbolAddress(sym), nil
	} else if err != nil {
		return 0, err
	} else if sym, err = m.findHashSymbol(name); sym != nil {
		return m.resolveSymbolAddress(sym), nil
	} else if err != nil {
		return 0, err
	}
	for _, sym := range m.symbols {
		if !IsImportSymbol(sym) && sym.Name == name {
			return m.resolveSymbolAddress(sym), nil
		}
	}
	return 0, debugger.ErrSymbolNotFound
}

func (m *module) Symbols(yield func(debugger.Symbol) bool) {
	count := uint32(len(m.hash.buckets))
	if count != 0 {
	} else if count = uint32(len(m.gnuHash.buckets)); count != 0 {
		count = m.gnuHash.buckets[count-1]
		for ; ; count++ {
			if m.getGNUChain(count-m.gnuHash.symbias)&1 != 0 {
				break
			}
		}
		count++
	}
	for i := uint32(1); i < count; i++ {
		sym := m.GetSymbol(i)
		if IsImportSymbol(sym) {
			continue
		} else if !yield(debugger.Symbol{Name: sym.Name, Value: m.resolveSymbolAddress(sym)}) {
			break
		}
	}
}

func (m *module) Class() elf.Class {
	return m.header.Class
}

func (m *module) DynValue(tag elf.DynTag) []uint64 {
	return m.dynamic[tag]
}

func (m *module) Needed() []string {
	return m.needed
}

func (m *module) GetSymbol(index uint32) *elf.Symbol {
	count := uint32(len(m.symbols))
	if index < count {
		return m.symbols[index]
	}
	size := index - count + 1
	ent := m.dynamic[elf.DT_SYMENT]
	for i, v := range m.dynamic[elf.DT_SYMTAB] {
		n := uint32(ent[i])
		sr := m.sectionReader(v+uint64(count*n), uint64(size*n))
		switch m.header.Class {
		case elf.ELFCLASS32:
			m.parseSym32(sr)
		case elf.ELFCLASS64:
			m.parseSym64(sr)
		}
		count = uint32(len(m.symbols))
		if index < count {
			return m.symbols[index]
		}
		size = index - count + 1
	}
	return nil
}

func (m *module) Reloc(rel any) {
	infos := relInfoMap[m.header.Machine]
	if len(infos) == 0 {
		return
	}
	emu := m.dbg.Emulator()
	switch rel := rel.(type) {
	case elf.Rel32:
		sym := m.GetSymbol(elf.R_SYM32(rel.Info))
		if info, ok := infos[elf.R_TYPE32(rel.Info)]; ok {
			addr := m.BaseAddr() + uint64(rel.Off)
			size := uint64(elf.R_SYM32(info))
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, 0)
			case relType_Value:
				if sym != nil {
					value := m.BaseAddr() + sym.Value
					emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
				}
			}
		}
	case elf.Rel64:
		sym := m.GetSymbol(elf.R_SYM64(rel.Info))
		if info, ok := infos[elf.R_TYPE64(rel.Info)]; ok {
			addr := m.BaseAddr() + rel.Off
			size := uint64(elf.R_SYM32(info))
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, 0)
			case relType_Value:
				if sym != nil {
					value := m.BaseAddr() + sym.Value
					emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
				}
			}
		}
	case elf.Rela32:
		sym := m.GetSymbol(elf.R_SYM32(rel.Info))
		if info, ok := infos[elf.R_TYPE32(rel.Info)]; ok {
			addr := m.BaseAddr() + uint64(rel.Off)
			size := uint64(elf.R_SYM32(info))
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, uint64(rel.Addend))
			case relType_Value:
				value := m.BaseAddr() + uint64(rel.Addend)
				if sym != nil {
					value += sym.Value
				}
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			}
		}
	case elf.Rela64:
		sym := m.GetSymbol(elf.R_SYM64(rel.Info))
		if info, ok := infos[elf.R_TYPE64(rel.Info)]; ok {
			addr := m.BaseAddr() + rel.Off
			size := uint64(elf.R_SYM32(info))
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, uint64(rel.Addend))
			case relType_Value:
				value := m.BaseAddr() + uint64(rel.Addend)
				if sym != nil {
					value += sym.Value
				}
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			}
		}
	}
}

func (m *module) findHashSymbol(name string) (*elf.Symbol, error) {
	if len(m.hash.buckets) == 0 {
		return nil, nil
	}
	h := elfHash(name)
	index := m.hash.buckets[h%uint32(len(m.hash.buckets))]
	for index != 0 {
		sym := m.GetSymbol(index)
		if sym == nil {
			break
		}
		if sym.Name == name {
			if IsImportSymbol(sym) {
				break
			}
			return sym, nil
		}
		index = m.hash.chains[index]
	}
	return nil, debugger.ErrSymbolNotFound
}

func (m *module) findGNUHashSymbol(name string) (*elf.Symbol, error) {
	if len(m.gnuHash.buckets) == 0 {
		return nil, nil
	}
	h := gnuHash(name)
	var bits uint32
	switch m.header.Class {
	case elf.ELFCLASS32:
		bits = 32
	case elf.ELFCLASS64:
		bits = 64
	}
	index := m.gnuHash.indexes[(h/bits)%uint32(len(m.gnuHash.indexes))]
	mask := (uint64(1) << (h % bits)) | (uint64(1) << ((h >> m.gnuHash.shift) % bits))
	if (index & mask) != mask {
		return nil, debugger.ErrSymbolNotFound
	}
	idx := m.gnuHash.buckets[h%uint32(len(m.gnuHash.buckets))]
	if idx < m.gnuHash.symbias {
		return nil, debugger.ErrSymbolNotFound
	}
	for ; ; idx++ {
		sym := m.GetSymbol(idx)
		if sym == nil {
			break
		}
		if sym.Name == name {
			if IsImportSymbol(sym) {
				break
			}
			return sym, nil
		}
		if m.getGNUChain(idx-m.gnuHash.symbias)&1 != 0 {
			break
		}
	}
	return nil, debugger.ErrSymbolNotFound
}

func (m *module) relocation() {
	const (
		DT_RELR elf.DynTag = 0x6fffe000 + iota
		DT_RELRSZ
	)

	sz := m.dynamic[elf.DT_RELSZ]
	for i, v := range m.dynamic[elf.DT_REL] {
		sr := m.sectionReader(v, sz[i])
		switch m.header.Class {
		case elf.ELFCLASS32:
			m.handleRel32(sr)
		case elf.ELFCLASS64:
			m.handleRel64(sr)
		}
	}
	sz = m.dynamic[elf.DT_RELASZ]
	for i, v := range m.dynamic[elf.DT_RELA] {
		sr := m.sectionReader(v, sz[i])
		switch m.header.Class {
		case elf.ELFCLASS32:
			m.handleRela32(sr)
		case elf.ELFCLASS64:
			m.handleRela64(sr)
		}
	}
	sz = m.dynamic[DT_RELRSZ]
	for i, v := range m.dynamic[DT_RELR] {
		sr := m.sectionReader(v, sz[i])
		switch m.header.Class {
		case elf.ELFCLASS32:
			m.handleRelr32(sr)
		case elf.ELFCLASS64:
			m.handleRelr64(sr)
		}
	}
	plt := m.dynamic[elf.DT_PLTREL]
	sz = m.dynamic[elf.DT_PLTRELSZ]
	for i, v := range m.dynamic[elf.DT_JMPREL] {
		sr := m.sectionReader(v, sz[i])
		switch elf.DynTag(plt[i]) {
		case elf.DT_REL:
			switch m.header.Class {
			case elf.ELFCLASS32:
				m.handleRel32(sr)
			case elf.ELFCLASS64:
				m.handleRel64(sr)
			}
		case elf.DT_RELA:
			switch m.header.Class {
			case elf.ELFCLASS32:
				m.handleRela32(sr)
			case elf.ELFCLASS64:
				m.handleRela64(sr)
			}
		}
	}
}

func (m *module) sectionReader(offset uint64, size uint64) *io.SectionReader {
	return io.NewSectionReader(m.dbg.ToPointer(m.BaseAddr()), int64(offset), int64(size))
}

func (m *module) getString(start uint32) string {
	sz := m.dynamic[elf.DT_STRSZ]
	for i, v := range m.dynamic[elf.DT_STRTAB] {
		sr := m.sectionReader(v, sz[i])
		var data []byte
		var buf [0x10]byte
		for begin := int64(start); ; {
			n, _ := sr.ReadAt(buf[:], begin)
			if n == 0 {
				break
			}
			i := slices.Index(buf[:n], 0)
			if i == -1 {
				data = append(data, buf[:n]...)
				begin += int64(n)
			} else {
				data = append(data, buf[:i]...)
				break
			}
		}
		if len(data) != 0 {
			return string(data)
		}
	}
	return ""
}

func (m *module) getGNUChain(index uint32) uint32 {
	if index < uint32(len(m.gnuHash.chains)) {
		return m.gnuHash.chains[index]
	}
	x := int(index) - len(m.gnuHash.chains)
	chains := make([]uint32, x+1)
	for i := 0; i <= x; i++ {
		binary.Read(m.gnuHash.sr, m.header.ByteOrder, &chains[i])
	}
	m.gnuHash.chains = append(m.gnuHash.chains, chains...)
	return chains[x]

}

func (m *module) progByType(typ elf.ProgType) *elf.ProgHeader {
	for i := range m.progs {
		prog := &m.progs[i]
		if prog.Type == typ {
			return prog
		}
	}
	return nil
}

func (m *module) parseDynamic() {
	ds := m.progByType(elf.PT_DYNAMIC)
	if ds == nil {
		return
	}
	sr := m.sectionReader(ds.Vaddr, ds.Memsz)
	switch m.header.Class {
	case elf.ELFCLASS32:
		m.parseDyn32(sr)
	case elf.ELFCLASS64:
		m.parseDyn64(sr)
	}
}

func (m *module) parseHash() {
	for _, v := range m.dynamic[elf.DT_HASH] {
		sr := m.sectionReader(v, math.MaxUint64)
		var nbucket, nchain uint32
		binary.Read(sr, m.header.ByteOrder, &nbucket)
		binary.Read(sr, m.header.ByteOrder, &nchain)
		m.hash.buckets = make([]uint32, nbucket)
		m.hash.chains = make([]uint32, nchain)
		for i := 0; i < int(nbucket); i++ {
			binary.Read(sr, m.header.ByteOrder, &m.hash.buckets[i])
		}
		for i := 0; i < int(nchain); i++ {
			binary.Read(sr, m.header.ByteOrder, &m.hash.chains[i])
		}
		break
	}
	for _, v := range m.dynamic[elf.DT_GNU_HASH] {
		sr := m.sectionReader(v, math.MaxUint64)
		var nbucket, nbitmask uint32
		binary.Read(sr, m.header.ByteOrder, &nbucket)
		binary.Read(sr, m.header.ByteOrder, &m.gnuHash.symbias)
		binary.Read(sr, m.header.ByteOrder, &nbitmask)
		binary.Read(sr, m.header.ByteOrder, &m.gnuHash.shift)
		m.gnuHash.indexes = make([]uint64, nbitmask)
		m.gnuHash.buckets = make([]uint32, nbucket)
		for i := 0; i < int(nbitmask); i++ {
			switch m.header.Class {
			case elf.ELFCLASS32:
				var index uint32
				binary.Read(sr, m.header.ByteOrder, &index)
				m.gnuHash.indexes[i] = uint64(index)
			case elf.ELFCLASS64:
				binary.Read(sr, m.header.ByteOrder, &m.gnuHash.indexes[i])
			}
		}
		for i := 0; i < int(nbucket); i++ {
			binary.Read(sr, m.header.ByteOrder, &m.gnuHash.buckets[i])
		}
		m.gnuHash.sr = sr
		break
	}
}

func (m *module) parseName() {
	for _, v := range m.dynamic[elf.DT_SONAME] {
		m.name = m.getString(uint32(v))
		break
	}
}

func (m *module) parseNeeded() {
	for _, v := range m.dynamic[elf.DT_NEEDED] {
		m.needed = append(m.needed, m.getString(uint32(v)))
	}
}

func (m *module) parseDyn32(r io.Reader) {
	for {
		var dyn elf.Dyn32
		err := binary.Read(r, m.header.ByteOrder, &dyn)
		if err != nil {
			break
		}
		tag := elf.DynTag(dyn.Tag)
		if tag == elf.DT_NULL {
			break
		}
		m.dynamic[tag] = append(m.dynamic[tag], uint64(dyn.Val))
	}
}

func (m *module) parseDyn64(r io.Reader) {
	for {
		var dyn elf.Dyn64
		err := binary.Read(r, m.header.ByteOrder, &dyn)
		if err != nil {
			break
		}
		tag := elf.DynTag(dyn.Tag)
		if tag == elf.DT_NULL {
			break
		}
		m.dynamic[tag] = append(m.dynamic[tag], dyn.Val)
	}
}

func (m *module) parseSym32(r io.Reader) {
	for {
		var sym elf.Sym32
		err := binary.Read(r, m.header.ByteOrder, &sym)
		if err != nil {
			break
		}
		m.symbols = append(m.symbols, &elf.Symbol{
			Name:    m.getString(sym.Name),
			Info:    sym.Info,
			Other:   sym.Other,
			Section: elf.SectionIndex(sym.Shndx),
			Value:   uint64(sym.Value),
			Size:    uint64(sym.Size),
		})
	}
}

func (m *module) parseSym64(r io.Reader) {
	for {
		var sym elf.Sym64
		err := binary.Read(r, m.header.ByteOrder, &sym)
		if err != nil {
			break
		}
		m.symbols = append(m.symbols, &elf.Symbol{
			Name:    m.getString(sym.Name),
			Info:    sym.Info,
			Other:   sym.Other,
			Section: elf.SectionIndex(sym.Shndx),
			Value:   sym.Value,
			Size:    sym.Size,
		})
	}
}

func (m *module) handleRel32(r io.Reader) {
	infos := relInfoMap[m.header.Machine]
	if len(infos) == 0 {
		return
	}
	emu := m.dbg.Emulator()
	for {
		var rel elf.Rel32
		err := binary.Read(r, m.header.ByteOrder, &rel)
		if err != nil {
			break
		}
		sym := m.GetSymbol(elf.R_SYM32(rel.Info))
		if info, ok := infos[elf.R_TYPE32(rel.Info)]; ok {
			addr := m.BaseAddr() + uint64(rel.Off)
			size := uint64(elf.R_SYM32(info))
			addend := uint64(0)
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, addend)
			case relType_Addend:
				emu.MemReadPtr(addr, size, unsafe.Pointer(&addend))
				fallthrough
			case relType_Value:
				value := m.BaseAddr() + addend
				if sym != nil {
					value += sym.Value
				}
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			case relType_Resolver:
				emu.MemReadPtr(addr, size, unsafe.Pointer(&addend))
				value, _ := m.resolve(context.TODO(), m.BaseAddr()+addend)
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			}
		}
	}
}

func (m *module) handleRel64(r io.Reader) {
	infos := relInfoMap[m.header.Machine]
	if len(infos) == 0 {
		return
	}
	emu := m.dbg.Emulator()
	for {
		var rel elf.Rel64
		err := binary.Read(r, m.header.ByteOrder, &rel)
		if err != nil {
			break
		}
		sym := m.GetSymbol(elf.R_SYM64(rel.Info))
		if info, ok := infos[elf.R_TYPE64(rel.Info)]; ok {
			addr := m.BaseAddr() + rel.Off
			size := uint64(elf.R_SYM32(info))
			addend := uint64(0)
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, addend)
			case relType_Addend:
				emu.MemReadPtr(addr, size, unsafe.Pointer(&addend))
				fallthrough
			case relType_Value:
				value := m.BaseAddr() + addend
				if sym != nil {
					value += sym.Value
				}
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			case relType_Resolver:
				emu.MemReadPtr(addr, size, unsafe.Pointer(&addend))
				value, _ := m.resolve(context.TODO(), m.BaseAddr()+addend)
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			}
		}
	}
}

func (m *module) handleRela32(r io.Reader) {
	infos := relInfoMap[m.header.Machine]
	if len(infos) == 0 {
		return
	}
	emu := m.dbg.Emulator()
	for {
		var rela elf.Rela32
		err := binary.Read(r, m.header.ByteOrder, &rela)
		if err != nil {
			break
		}
		sym := m.GetSymbol(elf.R_SYM32(rela.Info))
		if info, ok := infos[elf.R_TYPE32(rela.Info)]; ok {
			addr := m.BaseAddr() + uint64(rela.Off)
			size := uint64(elf.R_SYM32(info))
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, uint64(rela.Addend))
			case relType_Value, relType_Addend:
				value := m.BaseAddr() + uint64(rela.Addend)
				if sym != nil {
					value += sym.Value
				}
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			case relType_Resolver:
				value, _ := m.resolve(context.TODO(), m.BaseAddr()+uint64(rela.Addend))
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			}
		}
	}
}

func (m *module) handleRela64(r io.Reader) {
	infos := relInfoMap[m.header.Machine]
	if len(infos) == 0 {
		return
	}
	emu := m.dbg.Emulator()
	for {
		var rela elf.Rela64
		err := binary.Read(r, m.header.ByteOrder, &rela)
		if err != nil {
			break
		}
		sym := m.GetSymbol(elf.R_SYM64(rela.Info))
		if info, ok := infos[elf.R_TYPE64(rela.Info)]; ok {
			addr := m.BaseAddr() + rela.Off
			size := uint64(elf.R_SYM32(info))
			switch elf.R_TYPE32(info) {
			case relType_Import:
				m.handleImport(sym, addr, size, uint64(rela.Addend))
			case relType_Value, relType_Addend:
				value := m.BaseAddr() + uint64(rela.Addend)
				if sym != nil {
					value += sym.Value
				}
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			case relType_Resolver:
				value, _ := m.resolve(context.TODO(), m.BaseAddr()+uint64(rela.Addend))
				emu.MemWritePtr(addr, size, unsafe.Pointer(&value))
			}
		}
	}
}

func (m *module) handleRelr32(r io.Reader) {
	const wordsize = 4

	var base uint64
	for _, entry := range m.parseArray32(r) {
		if entry&1 == 0 {
			m.handleRelative(m.BaseAddr()+entry, wordsize)
			base = entry + wordsize
			continue
		}
		offset := base
		for entry != 0 {
			entry >>= 1
			if entry&1 != 0 {
				m.handleRelative(m.BaseAddr()+offset, wordsize)
			}
			offset += wordsize
		}
		base += (8*wordsize - 1) * wordsize
	}
}

func (m *module) handleRelr64(r io.Reader) {
	const wordsize = 8

	var base uint64
	for _, entry := range m.parseArray64(r) {
		if entry&1 == 0 {
			m.handleRelative(m.BaseAddr()+entry, wordsize)
			base = entry + wordsize
			continue
		}
		offset := base
		for entry != 0 {
			entry >>= 1
			if entry&1 != 0 {
				m.handleRelative(m.BaseAddr()+offset, wordsize)
			}
			offset += wordsize
		}
		base += (8*wordsize - 1) * wordsize
	}
}

func (m *module) handleRelative(addr, size uint64) {
	ptr := m.dbg.ToPointer(addr)
	var value uint64
	ptr.MemReadPtr(size, unsafe.Pointer(&value))
	value += m.BaseAddr()
	ptr.MemWritePtr(size, unsafe.Pointer(&value))
}

func (m *module) handleImport(sym *elf.Symbol, addr, size, added uint64) {
	if sym == nil {
		return
	}
	var value uint64
	if IsImportSymbol(sym) {
		for _, name := range m.needed {
			module, err := m.dbg.FindModule(name)
			if err != nil {
				continue
			}
			symAddr, err := module.FindSymbol(sym.Name)
			if err != nil {
				continue
			}
			value = symAddr + added
			break
		}
		if value == 0 {
			value, _ = m.addSymbolHandler(sym, addr, size, added)
		}
	} else {
		value = m.resolveSymbolAddress(sym) + added
	}
	m.dbg.Emulator().MemWritePtr(addr, size, unsafe.Pointer(&value))
}

func (m *module) addSymbolHandler(sym *elf.Symbol, addr, size, added uint64) (uint64, error) {
	data := &relData{sym: sym, addr: addr, size: size, added: added}
	ctrl, err := m.dbg.AddControl(m.handleRelocation, data)
	if err != nil {
		return 0, err
	}
	data.ctrl = ctrl
	m.rels = append(m.rels, ctrl)
	return ctrl.Addr(), nil
}

func (m *module) handleRelocation(ctx debugger.Context, data any) {
	dbg := ctx.Debugger()
	rd := data.(*relData)
	_, addr, err := dbg.FindSymbol(rd.sym.Name)
	if err != nil {
		panic(fmt.Errorf("%s: %w", rd.sym.Name, err))
	}
	addr += rd.added
	ctx.ToPointer(rd.addr).MemWritePtr(rd.size, unsafe.Pointer(&addr))
	ctx.RegWrite(ctx.PC(), addr)
	rd.ctrl.Close()
	m.mu.Lock()
	m.rels = slices.DeleteFunc(m.rels, func(ctrl debugger.ControlHandler) bool { return ctrl == rd.ctrl })
	m.mu.Unlock()
}

func (m *module) resolveSymbolAddress(sym *elf.Symbol) uint64 {
	if elf.ST_TYPE(sym.Info) != elf.STT_GNU_IFUNC {
		return m.BaseAddr() + sym.Value
	} else if value, ok := m.ifunc.Load(sym.Value); ok {
		return value.(uint64)
	}
	value, _ := m.resolve(context.TODO(), m.BaseAddr()+sym.Value)
	m.ifunc.Store(sym.Value, value)
	return value
}

func (m *module) call(ctx context.Context, addr uint64) error {
	task, err := m.dbg.CreateTask(ctx)
	if err != nil {
		return err
	}
	defer task.Close()
	err = m.dbg.CallTaskOf(task, addr)
	if err != nil {
		return err
	}
	return task.SyncRun()
}

func (m *module) resolve(ctx context.Context, addr uint64) (uint64, error) {
	task, err := m.dbg.CreateTask(ctx)
	if err != nil {
		return 0, err
	}
	defer task.Close()
	err = m.dbg.CallTaskOf(task, addr)
	if err != nil {
		return 0, err
	}
	err = task.SyncRun()
	if err != nil {
		return 0, err
	}
	var r uintptr
	task.Context().RetExtract(&r)
	return uint64(r), nil
}

func (m *module) parseArray32(r io.Reader) (arr []uint64) {
	for {
		var value uint32
		err := binary.Read(r, m.header.ByteOrder, &value)
		if err != nil {
			break
		}
		arr = append(arr, uint64(value))
	}
	return
}

func (m *module) parseArray64(r io.Reader) (arr []uint64) {
	for {
		var value uint64
		err := binary.Read(r, m.header.ByteOrder, &value)
		if err != nil {
			break
		}
		arr = append(arr, value)
	}
	return
}

func IsImportSymbol(sym *elf.Symbol) bool {
	if sym.Section != elf.SHN_UNDEF {
		return false
	}
	bind := elf.ST_BIND(sym.Info)
	return bind == elf.STB_GLOBAL || bind == elf.STB_WEAK
}
