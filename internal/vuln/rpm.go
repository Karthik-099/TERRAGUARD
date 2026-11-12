package vuln

import (
	"encoding/binary"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
)

// RPM package inventory for RHEL and other rpm-based images. The rpm
// database comes in three formats, all read here without cgo or a library:
// Berkeley DB hash (RHEL 7/8, var/lib/rpm/Packages), SQLite (RHEL 9, UBI 9,
// Fedora, rpmdb.sqlite) and ndb (SUSE, Packages.db). Each holds one rpm
// header blob per installed package. Every offset is checked before use.

const (
	maxRPMHeaderIndex = 0xffff   // rpm's own limit on header entries
	maxRPMHeaderData  = 64 << 20 // rpm allows 256 MB; real headers are under 1 MB
	maxRPMPackages    = 100000
	maxRPMBlob        = 16 << 20 // one package's header, overflow pages joined
)

var errRPMCorrupt = errors.New("rpm database is corrupt or truncated")

// rpmPackage is what the scan needs from one header.
type rpmPackage struct {
	Name, Version, Release, Arch, SourceRPM string
	Epoch                                   int // -1 when the header has none
}

// EVR is the version as OSV's rpm ecosystems write it: [epoch:]version-release.
func (p rpmPackage) EVR() string {
	v := p.Version + "-" + p.Release
	if p.Epoch > 0 {
		v = strconv.Itoa(p.Epoch) + ":" + v
	}
	return v
}

// isRPMDB names the rpm database files an image may hold.
func isRPMDB(name string) bool {
	switch name {
	case "var/lib/rpm/Packages", "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/Packages.db",
		"usr/lib/sysimage/rpm/Packages", "usr/lib/sysimage/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/Packages.db":
		return true
	}
	return false
}

// parseRPMDB lists the packages in an rpm database file. OSV's rpm
// ecosystems name binary packages (openssl-libs), so Name is the rpm name.
func parseRPMDB(file string, b []byte, eco string) ([]Package, error) {
	var blobs [][]byte
	var err error
	switch {
	case len(b) >= 16 && string(b[:16]) == "SQLite format 3\x00":
		blobs, err = sqliteRPMBlobs(b)
	case len(b) >= 4 && binary.LittleEndian.Uint32(b) == ndbMagic:
		blobs, err = ndbBlobs(b)
	default:
		blobs, err = bdbHashValues(b)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path.Base(file), err)
	}
	var out []Package
	for _, blob := range blobs {
		p, err := parseRPMHeader(blob)
		if err != nil || p.Name == "" || p.Name == "gpg-pubkey" { // gpg-pubkey entries are imported keys, not software
			continue
		}
		out = append(out, Package{Ecosystem: eco, Name: p.Name, Version: p.EVR(), File: file})
	}
	return out, nil
}

// --- rpm header ---

const (
	rpmTagName      = 1000
	rpmTagVersion   = 1001
	rpmTagRelease   = 1002
	rpmTagEpoch     = 1003
	rpmTagArch      = 1022
	rpmTagSourceRPM = 1044

	rpmTypeInt32  = 4
	rpmTypeString = 6
)

// parseRPMHeader reads a header blob as stored in the database: entry count,
// data length, the entries, then the data store (no lead or magic).
func parseRPMHeader(b []byte) (rpmPackage, error) {
	p := rpmPackage{Epoch: -1}
	if len(b) < 8 {
		return p, errRPMCorrupt
	}
	il, dl := binary.BigEndian.Uint32(b), binary.BigEndian.Uint32(b[4:])
	if il == 0 || il > maxRPMHeaderIndex || dl > maxRPMHeaderData {
		return p, errRPMCorrupt
	}
	dataStart := 8 + 16*uint64(il)
	if dataStart+uint64(dl) > uint64(len(b)) {
		return p, errRPMCorrupt
	}
	data := b[dataStart : dataStart+uint64(dl)]
	for i := uint64(0); i < uint64(il); i++ {
		e := b[8+16*i : 24+16*i]
		tag, typ, off, cnt := binary.BigEndian.Uint32(e), binary.BigEndian.Uint32(e[4:]), binary.BigEndian.Uint32(e[8:]), binary.BigEndian.Uint32(e[12:])
		if uint64(off) >= uint64(len(data)) {
			continue
		}
		switch {
		case typ == rpmTypeString && cnt == 1:
			s := data[off:]
			n := 0
			for n < len(s) && s[n] != 0 {
				n++
			}
			if n == len(s) {
				continue // unterminated
			}
			v := string(s[:n])
			switch tag {
			case rpmTagName:
				p.Name = v
			case rpmTagVersion:
				p.Version = v
			case rpmTagRelease:
				p.Release = v
			case rpmTagArch:
				p.Arch = v
			case rpmTagSourceRPM:
				p.SourceRPM = v
			}
		case typ == rpmTypeInt32 && cnt >= 1 && tag == rpmTagEpoch && uint64(off)+4 <= uint64(len(data)):
			if ep := binary.BigEndian.Uint32(data[off:]); ep <= 1<<30 {
				p.Epoch = int(ep)
			}
		}
	}
	if p.Name == "" || p.Version == "" {
		return p, errRPMCorrupt
	}
	return p, nil
}

// --- Berkeley DB hash (RHEL 7 and 8) ---

const (
	bdbHashMagic    = 0x061561
	bdbPageHeader   = 26
	bdbPageHash     = 13
	bdbPageHashOld  = 2 // P_HASH_UNSORTED
	bdbPageOverflow = 7
	bdbKeyData      = 1
	bdbOffPage      = 3
)

// bdbHashValues returns the data items of a Berkeley DB hash database.
// rpm stores each header as an overflow (off-page) item; small ones inline.
func bdbHashValues(b []byte) ([][]byte, error) {
	if len(b) < 512 {
		return nil, errors.New("not an rpm database (too short)")
	}
	var bo binary.ByteOrder = binary.LittleEndian
	switch {
	case binary.LittleEndian.Uint32(b[12:]) == bdbHashMagic:
	case binary.BigEndian.Uint32(b[12:]) == bdbHashMagic:
		bo = binary.BigEndian
	default:
		return nil, errors.New("not an rpm database (unknown format)")
	}
	pageSize := uint64(bo.Uint32(b[20:]))
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, errRPMCorrupt
	}
	pages := uint64(len(b)) / pageSize
	if last := uint64(bo.Uint32(b[32:])) + 1; last < pages {
		pages = last
	}
	page := func(n uint64) []byte {
		if n == 0 || n >= pages {
			return nil
		}
		return b[n*pageSize : (n+1)*pageSize]
	}
	var out [][]byte
	var copied uint64
	for n := uint64(1); n < pages && len(out) < maxRPMPackages; n++ {
		pg := page(n)
		if t := pg[25]; t != bdbPageHash && t != bdbPageHashOld {
			continue
		}
		entries := uint64(bo.Uint16(pg[20:]))
		if bdbPageHeader+2*entries > pageSize {
			continue
		}
		offs := make([]uint64, entries)
		for i := range offs {
			offs[i] = uint64(bo.Uint16(pg[bdbPageHeader+2*uint64(i):]))
		}
		for i := uint64(1); i < entries; i += 2 { // even items are keys, odd ones data
			off := offs[i]
			if off < bdbPageHeader || off >= pageSize {
				continue
			}
			switch pg[off] {
			case bdbOffPage:
				if off+12 > pageSize {
					continue
				}
				if v := bdbOverflow(page, bo, uint64(bo.Uint32(pg[off+4:])), uint64(bo.Uint32(pg[off+8:])), pageSize, uint64(len(b))); v != nil {
					// A valid database copies each overflow page once; entries sharing a chain would grow memory quadratically.
					if copied += uint64(len(v)); copied > 2*uint64(len(b)) {
						return nil, errRPMCorrupt
					}
					out = append(out, v)
				}
			case bdbKeyData:
				end := pageSize // items fill the page from the end, so the previous item bounds this one
				if offs[i-1] > off && offs[i-1] <= pageSize {
					end = offs[i-1]
				}
				out = append(out, pg[off+1:end])
			}
		}
	}
	return out, nil
}

// bdbOverflow joins an overflow chain, giving up on a loop or a short chain.
func bdbOverflow(page func(uint64) []byte, bo binary.ByteOrder, n, total, pageSize, fileSize uint64) []byte {
	if total == 0 || total > maxRPMBlob || total > fileSize {
		return nil
	}
	out := make([]byte, 0, total)
	seen := map[uint64]bool{}
	for n != 0 && uint64(len(out)) < total {
		pg := page(n)
		if pg == nil || seen[n] || pg[25] != bdbPageOverflow {
			return nil
		}
		seen[n] = true
		l := uint64(bo.Uint16(pg[22:])) // hf_offset holds the bytes used on an overflow page
		if bdbPageHeader+l > pageSize {
			return nil
		}
		out = append(out, pg[bdbPageHeader:bdbPageHeader+l]...)
		n = uint64(bo.Uint32(pg[16:]))
	}
	if uint64(len(out)) < total {
		return nil
	}
	return out[:total]
}

// --- ndb (rpm's own format, used by SUSE) ---

const (
	ndbMagic     = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	ndbSlotMagic = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
	ndbBlobMagic = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24
)

func ndbBlobs(b []byte) ([][]byte, error) {
	if len(b) < 32 {
		return nil, errRPMCorrupt
	}
	slotPages := uint64(binary.LittleEndian.Uint32(b[12:]))
	if slotPages == 0 || slotPages*4096 > uint64(len(b)) {
		return nil, errRPMCorrupt
	}
	var out [][]byte
	for off := uint64(32); off+16 <= slotPages*4096 && len(out) < maxRPMPackages; off += 16 {
		s := b[off:]
		if binary.LittleEndian.Uint32(s) != ndbSlotMagic || binary.LittleEndian.Uint32(s[4:]) == 0 {
			continue
		}
		idx, blk := binary.LittleEndian.Uint32(s[4:]), uint64(binary.LittleEndian.Uint32(s[8:]))*16
		if blk+16 > uint64(len(b)) {
			continue
		}
		h := b[blk:]
		size := uint64(binary.LittleEndian.Uint32(h[12:]))
		if binary.LittleEndian.Uint32(h) != ndbBlobMagic || binary.LittleEndian.Uint32(h[4:]) != idx || size > maxRPMBlob || blk+16+size > uint64(len(b)) {
			continue
		}
		out = append(out, h[16:16+size])
	}
	return out, nil
}

// --- SQLite (RHEL 9) ---

// sqliteRPMBlobs reads the blob column of the Packages table:
// CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL).
// shortcut: a -wal file is not replayed; images are built with a checkpointed database.
func sqliteRPMBlobs(b []byte) ([][]byte, error) {
	db, err := openSQLite(b)
	if err != nil {
		return nil, err
	}
	root := uint32(0)
	err = db.walk(1, func(rec [][]byte, types []uint64) {
		if len(rec) >= 4 && string(rec[0]) == "table" && string(rec[1]) == "Packages" {
			root = uint32(sqliteInt(rec[3], types[3]))
		}
	})
	if err != nil {
		return nil, err
	}
	if root == 0 {
		return nil, errors.New("rpmdb.sqlite has no Packages table")
	}
	var out [][]byte
	err = db.walk(root, func(rec [][]byte, types []uint64) {
		if len(rec) >= 2 && types[1] >= 12 && types[1]%2 == 0 && len(out) < maxRPMPackages {
			out = append(out, rec[1])
		}
	})
	return out, err
}

type sqliteDB struct {
	copied       uint64 // payload bytes copied so far; capped so shared cells cannot grow memory quadratically
	b            []byte
	pageSize     uint64
	usable       uint64
	pages        uint64
	visitedPages int
}

func openSQLite(b []byte) (*sqliteDB, error) {
	if len(b) < 100 {
		return nil, errRPMCorrupt
	}
	ps := uint64(binary.BigEndian.Uint16(b[16:]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps > 65536 || ps&(ps-1) != 0 || uint64(b[20]) >= ps-480 {
		return nil, errRPMCorrupt
	}
	return &sqliteDB{b: b, pageSize: ps, usable: ps - uint64(b[20]), pages: uint64(len(b)) / ps}, nil
}

func (db *sqliteDB) page(n uint64) []byte {
	if n == 0 || n > db.pages {
		return nil
	}
	return db.b[(n-1)*db.pageSize : n*db.pageSize]
}

// walk visits every row of the table b-tree rooted at page root.
func (db *sqliteDB) walk(root uint32, fn func(rec [][]byte, types []uint64)) error {
	return db.walkPage(uint64(root), 0, fn)
}

func (db *sqliteDB) walkPage(n uint64, depth int, fn func([][]byte, []uint64)) error {
	pg := db.page(n)
	if pg == nil || depth > 20 {
		return errRPMCorrupt
	}
	if db.visitedPages++; uint64(db.visitedPages) > 2*db.pages+16 {
		return errRPMCorrupt // a cycle in a corrupt file
	}
	hdr := uint64(0)
	if n == 1 {
		hdr = 100
	}
	if hdr+12 > uint64(len(pg)) {
		return errRPMCorrupt
	}
	typ := pg[hdr]
	cells := uint64(binary.BigEndian.Uint16(pg[hdr+3:]))
	ptrs := hdr + 8
	if typ == 0x05 {
		ptrs = hdr + 12
	}
	if ptrs+2*cells > db.usable {
		return errRPMCorrupt
	}
	for i := uint64(0); i < cells; i++ {
		c := uint64(binary.BigEndian.Uint16(pg[ptrs+2*i:]))
		if c < ptrs || c >= db.usable {
			return errRPMCorrupt
		}
		switch typ {
		case 0x05: // interior table: 4-byte left child, rowid
			if c+4 > db.usable {
				return errRPMCorrupt
			}
			if err := db.walkPage(uint64(binary.BigEndian.Uint32(pg[c:])), depth+1, fn); err != nil {
				return err
			}
		case 0x0d: // leaf table: payload size, rowid, payload
			size, k := sqliteVarint(pg[c:db.usable])
			if k == 0 {
				return errRPMCorrupt
			}
			_, k2 := sqliteVarint(pg[c+uint64(k) : db.usable])
			if k2 == 0 {
				return errRPMCorrupt
			}
			payload, err := db.payload(pg[:db.usable], c+uint64(k+k2), size)
			if err != nil {
				return err
			}
			if rec, types, ok := sqliteRecord(payload); ok {
				fn(rec, types)
			}
		default:
			return errRPMCorrupt
		}
	}
	if typ == 0x05 {
		return db.walkPage(uint64(binary.BigEndian.Uint32(pg[hdr+8:])), depth+1, fn)
	}
	return nil
}

// payload returns a cell's payload, following overflow pages when it spills.
func (db *sqliteDB) payload(pg []byte, at, size uint64) ([]byte, error) {
	if size > maxRPMBlob || size > uint64(len(db.b)) {
		return nil, errRPMCorrupt
	}
	if db.copied += size; db.copied > 2*uint64(len(db.b)) {
		return nil, errRPMCorrupt
	}
	u := db.usable
	x := u - 35
	local := size
	if size > x {
		m := (u-12)*32/255 - 23
		local = m + (size-m)%(u-4)
		if local > x {
			local = m
		}
	}
	if at+local > uint64(len(pg)) {
		return nil, errRPMCorrupt
	}
	out := append(make([]byte, 0, size), pg[at:at+local]...)
	if local == size {
		return out, nil
	}
	if at+local+4 > uint64(len(pg)) {
		return nil, errRPMCorrupt
	}
	next := uint64(binary.BigEndian.Uint32(pg[at+local:]))
	for hops := uint64(0); uint64(len(out)) < size; hops++ {
		op := db.page(next)
		if op == nil || hops > db.pages {
			return nil, errRPMCorrupt
		}
		n := min(size-uint64(len(out)), u-4)
		out = append(out, op[4:4+n]...)
		next = uint64(binary.BigEndian.Uint32(op))
	}
	return out, nil
}

// sqliteVarint decodes a big-endian base-128 varint; n is 0 when b is too short.
func sqliteVarint(b []byte) (v uint64, n int) {
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

// sqliteRecord splits a record into column bytes and their serial types.
func sqliteRecord(p []byte) (cols [][]byte, types []uint64, ok bool) {
	hlen, n := sqliteVarint(p)
	if n == 0 || hlen > uint64(len(p)) || hlen < uint64(n) {
		return nil, nil, false
	}
	body := hlen
	for at := uint64(n); at < hlen && len(types) < 64; {
		t, k := sqliteVarint(p[at:hlen])
		if k == 0 {
			return nil, nil, false
		}
		at += uint64(k)
		var size uint64
		switch {
		case t <= 4:
			size = []uint64{0, 1, 2, 3, 4}[t]
		case t == 5:
			size = 6
		case t == 6 || t == 7:
			size = 8
		case t >= 12:
			size = (t - 12) / 2
		}
		if body+size > uint64(len(p)) {
			return nil, nil, false
		}
		cols, types = append(cols, p[body:body+size]), append(types, t)
		body += size
	}
	return cols, types, true
}

// sqliteInt reads an integer column (serial types 1 to 6, 8 and 9).
func sqliteInt(b []byte, t uint64) int64 {
	switch t {
	case 8:
		return 0
	case 9:
		return 1
	}
	if t < 1 || t > 6 {
		return 0
	}
	var v int64
	for i, c := range b {
		if i == 0 {
			v = int64(int8(c))
			continue
		}
		v = v<<8 | int64(c)
	}
	return v
}

// --- os-release and versions ---

// rpmEcosystem maps os-release fields of an rpm-based distribution to its OSV
// ecosystem. Red Hat's OSV ecosystems carry a repository suffix
// ("Red Hat:enterprise_linux:9::baseos"), so its name here is a prefix that
// DB.Lookup must expand. Fedora, CentOS and Oracle Linux have no OSV data.
func rpmEcosystem(kv map[string]string) string {
	ver := kv["VERSION_ID"]
	major, _, _ := strings.Cut(ver, ".")
	if major == "" || !allDigits(major) {
		return ""
	}
	switch kv["ID"] {
	case "rhel":
		if len(major) > 1 { // RHEL 10 and later publish per minor release: enterprise_linux:10.0
			return "Red Hat:enterprise_linux:" + ver
		}
		return "Red Hat:enterprise_linux:" + major
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	case "mageia":
		return "Mageia:" + major
	case "azurelinux":
		return "Azure Linux:" + major
	}
	return ""
}

// compareRPM orders [epoch:]version[-release] strings as rpm does.
func compareRPM(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if c := cmpNum(ea, eb); c != 0 {
		return c
	}
	if c := rpmvercmp(va, vb); c != 0 || ra == "" || rb == "" {
		return c
	}
	return rpmvercmp(ra, rb)
}

func splitEVR(s string) (epoch, version, release string) {
	epoch = "0"
	if e, rest, ok := strings.Cut(s, ":"); ok && allDigits(e) {
		epoch, s = e, rest
	}
	if i := strings.LastIndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
}

func isAlnum(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// rpmvercmp is rpm's segment comparison, including ~ (sorts before anything,
// even the end) and ^ (sorts after the end but before any other segment).
func rpmvercmp(a, b string) int {
	if a == b {
		return 0
	}
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for i < len(a) && !isAlnum(a[i]) && a[i] != '~' && a[i] != '^' {
			i++
		}
		for j < len(b) && !isAlnum(b[j]) && b[j] != '~' && b[j] != '^' {
			j++
		}
		ta, tb := i < len(a) && a[i] == '~', j < len(b) && b[j] == '~'
		if ta || tb {
			if !ta {
				return 1
			}
			if !tb {
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		ca, cb := i < len(a) && a[i] == '^', j < len(b) && b[j] == '^'
		if ca || cb {
			switch {
			case i >= len(a):
				return -1
			case j >= len(b):
				return 1
			case !ca:
				return 1
			case !cb:
				return -1
			}
			i, j = i+1, j+1
			continue
		}
		if i >= len(a) || j >= len(b) {
			break
		}
		num := isDigit(a[i])
		class := func(c byte) bool { return isDigit(c) == num && isAlnum(c) }
		si, sj := i, j
		for i < len(a) && class(a[i]) {
			i++
		}
		for j < len(b) && class(b[j]) {
			j++
		}
		if sj == j { // segments of different kinds: a number is newer than letters
			if num {
				return 1
			}
			return -1
		}
		var c int
		if num {
			c = cmpNum(a[si:i], b[sj:j])
		} else {
			c = strings.Compare(a[si:i], b[sj:j])
		}
		if c != 0 {
			return c
		}
	}
	switch {
	case i >= len(a) && j >= len(b):
		return 0
	case i < len(a):
		return 1
	}
	return -1
}
