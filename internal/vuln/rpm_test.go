package vuln

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rpmHeaderBlob builds a header blob as the rpm database stores it.
func rpmHeaderBlob(name, version, release, arch string, epoch int) []byte {
	type ent struct{ tag, typ, off, cnt uint32 }
	var ents []ent
	var data []byte
	str := func(tag uint32, s string) {
		ents = append(ents, ent{tag, rpmTypeString, uint32(len(data)), 1})
		data = append(append(data, s...), 0)
	}
	str(rpmTagName, name)
	str(rpmTagVersion, version)
	str(rpmTagRelease, release)
	str(rpmTagArch, arch)
	str(rpmTagSourceRPM, name+"-"+version+"-"+release+".src.rpm")
	if epoch >= 0 {
		for len(data)%4 != 0 {
			data = append(data, 0)
		}
		ents = append(ents, ent{rpmTagEpoch, rpmTypeInt32, uint32(len(data)), 1})
		data = binary.BigEndian.AppendUint32(data, uint32(epoch))
	}
	b := binary.BigEndian.AppendUint32(nil, uint32(len(ents)))
	b = binary.BigEndian.AppendUint32(b, uint32(len(data)))
	for _, e := range ents {
		for _, v := range []uint32{e.tag, e.typ, e.off, e.cnt} {
			b = binary.BigEndian.AppendUint32(b, v)
		}
	}
	return append(b, data...)
}

// testBlobs are three packages; the padded one needs overflow pages in every format.
func testBlobs() [][]byte {
	big := rpmHeaderBlob("openssl-libs", "3.0.7", "24.el9", "x86_64", 1)
	big = append(big, make([]byte, 9000)...) // trailing bytes past the data store are ignored
	return [][]byte{
		rpmHeaderBlob("bash", "5.1.8", "9.el9", "x86_64", -1),
		big,
		rpmHeaderBlob("gpg-pubkey", "fd431d51", "4ae0493b", "(none)", -1),
	}
}

const wantRPM = "Red Hat:enterprise_linux:9:bash@5.1.8-9.el9 Red Hat:enterprise_linux:9:openssl-libs@1:3.0.7-24.el9"

// sqliteFixture writes a database holding sqlite_master and a Packages table,
// one leaf page each, with overflow pages for payloads that do not fit.
func sqliteFixture(blobs [][]byte) []byte {
	const ps = 1024
	pages := [][]byte{make([]byte, ps), make([]byte, ps)}
	varint := func(b []byte, v uint64) []byte {
		if v < 0x80 {
			return append(b, byte(v))
		}
		if v < 0x4000 {
			return append(b, byte(v>>7)|0x80, byte(v&0x7f))
		}
		return append(b, byte(v>>14)|0x80, byte(v>>7)|0x80, byte(v&0x7f))
	}
	record := func(cols ...any) []byte {
		var hdr, body []byte
		for _, c := range cols {
			switch v := c.(type) {
			case nil:
				hdr = varint(hdr, 0)
			case int:
				hdr, body = varint(hdr, 1), append(body, byte(v))
			case string:
				hdr, body = varint(hdr, uint64(13+2*len(v))), append(body, v...)
			case []byte:
				hdr, body = varint(hdr, uint64(12+2*len(v))), append(body, v...)
			}
		}
		return append(append(varint(nil, uint64(len(hdr)+1)), hdr...), body...)
	}
	leaf := func(pg []byte, hdrAt int, rows [][]byte) {
		pg[hdrAt] = 0x0d
		binary.BigEndian.PutUint16(pg[hdrAt+3:], uint16(len(rows)))
		end := ps
		u := uint64(ps)
		for i, p := range rows {
			size := uint64(len(p))
			local := size
			if x := u - 35; size > x {
				m := (u-12)*32/255 - 23
				if local = m + (size-m)%(u-4); local > x {
					local = m
				}
			}
			cell := varint(varint(nil, size), uint64(i+1))
			cell = append(cell, p[:local]...)
			if local < size {
				cell = binary.BigEndian.AppendUint32(cell, uint32(len(pages)+1))
				for rest := p[local:]; len(rest) > 0; {
					n := min(len(rest), ps-4)
					op := make([]byte, ps)
					if len(rest) > n {
						binary.BigEndian.PutUint32(op, uint32(len(pages)+2))
					}
					copy(op[4:], rest[:n])
					pages, rest = append(pages, op), rest[n:]
				}
			}
			end -= len(cell)
			copy(pg[end:], cell)
			binary.BigEndian.PutUint16(pg[hdrAt+8+2*i:], uint16(end))
		}
		binary.BigEndian.PutUint16(pg[hdrAt+5:], uint16(end))
	}
	leaf(pages[0], 100, [][]byte{record("table", "Packages", "Packages", 2, "CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)")})
	var rows [][]byte
	for _, b := range blobs {
		rows = append(rows, record(nil, b))
	}
	leaf(pages[1], 0, rows)
	copy(pages[0], "SQLite format 3\x00")
	binary.BigEndian.PutUint16(pages[0][16:], ps)
	var out []byte
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

// bdbFixture writes a little-endian hash database: meta page, one hash page
// with off-page items, and the overflow chains.
func bdbFixture(blobs [][]byte) []byte {
	const ps = 4096
	le := binary.LittleEndian
	pages := [][]byte{make([]byte, ps), make([]byte, ps)}
	hash := pages[1]
	hash[25] = bdbPageHash
	le.PutUint16(hash[20:], uint16(2*len(blobs)))
	end := ps
	for i, b := range blobs {
		key := []byte{bdbKeyData, byte(i + 1), 0, 0, 0}
		end -= len(key)
		copy(hash[end:], key)
		le.PutUint16(hash[bdbPageHeader+4*i:], uint16(end))
		item := make([]byte, 12)
		item[0] = bdbOffPage
		le.PutUint32(item[4:], uint32(len(pages)))
		le.PutUint32(item[8:], uint32(len(b)))
		end -= len(item)
		copy(hash[end:], item)
		le.PutUint16(hash[bdbPageHeader+4*i+2:], uint16(end))
		for rest := b; len(rest) > 0; {
			n := min(len(rest), ps-bdbPageHeader)
			op := make([]byte, ps)
			op[25] = bdbPageOverflow
			le.PutUint16(op[22:], uint16(n))
			if len(rest) > n {
				le.PutUint32(op[16:], uint32(len(pages)+1))
			}
			copy(op[bdbPageHeader:], rest[:n])
			pages, rest = append(pages, op), rest[n:]
		}
	}
	le.PutUint32(pages[0][12:], bdbHashMagic)
	le.PutUint32(pages[0][20:], ps)
	le.PutUint32(pages[0][32:], uint32(len(pages)-1))
	pages[0][25] = 8
	var out []byte
	for _, p := range pages {
		out = append(out, p...)
	}
	return out
}

func ndbFixture(blobs [][]byte) []byte {
	le := binary.LittleEndian
	out := make([]byte, 4096)
	le.PutUint32(out, ndbMagic)
	le.PutUint32(out[12:], 1)
	for i, b := range blobs {
		slot := out[32+16*i:]
		le.PutUint32(slot, ndbSlotMagic)
		le.PutUint32(slot[4:], uint32(i+1))
		le.PutUint32(slot[8:], uint32(len(out)/16))
		h := make([]byte, 16)
		le.PutUint32(h, ndbBlobMagic)
		le.PutUint32(h[4:], uint32(i+1))
		le.PutUint32(h[12:], uint32(len(b)))
		out = append(append(out, h...), b...)
		for len(out)%16 != 0 {
			out = append(out, 0)
		}
	}
	return out
}

func TestParseRPMDB(t *testing.T) {
	eco := rpmEcosystem(map[string]string{"ID": "rhel", "VERSION_ID": "9.4"})
	for name, db := range map[string][]byte{
		"var/lib/rpm/rpmdb.sqlite": sqliteFixture(testBlobs()),
		"var/lib/rpm/Packages":     bdbFixture(testBlobs()),
		"var/lib/rpm/Packages.db":  ndbFixture(testBlobs()),
	} {
		ps, err := parseRPMDB(name, db, eco)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := pkgSet(ps); got != wantRPM {
			t.Errorf("%s:\n got %s\nwant %s", name, got, wantRPM)
		}
		if !isRPMDB(name) {
			t.Errorf("isRPMDB(%s) = false", name)
		}
	}
	p, err := parseRPMHeader(testBlobs()[1])
	if err != nil || p.Arch != "x86_64" || p.SourceRPM != "openssl-libs-3.0.7-24.el9.src.rpm" || p.Epoch != 1 {
		t.Errorf("header: %+v %v", p, err)
	}
}

// TestParseRPMDBTruncated: every prefix of a valid file must fail cleanly.
func TestParseRPMDBTruncated(t *testing.T) {
	for _, db := range [][]byte{sqliteFixture(testBlobs()), bdbFixture(testBlobs()), ndbFixture(testBlobs())} {
		for n := 0; n < len(db); n += 97 {
			_, _ = parseRPMDB("var/lib/rpm/Packages", db[:n], "")
		}
	}
	for n := range testBlobs()[1] {
		_, _ = parseRPMHeader(testBlobs()[1][:n])
	}
}

// TestRPMDBReal reads databases taken from real images, for example
// RPMDB_DIR=<dir with ubi8/var/lib/rpm/Packages and ubi9/var/lib/rpm/rpmdb.sqlite>.
func TestRPMDBReal(t *testing.T) {
	dir := os.Getenv("RPMDB_DIR")
	if dir == "" {
		t.Skip("set RPMDB_DIR to a folder holding rpm databases")
	}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !isRPMDB("var/lib/rpm/"+d.Name()) {
			return nil
		}
		b, _ := os.ReadFile(p)
		ps, err := parseRPMDB(p, b, "x")
		if err != nil || len(ps) == 0 {
			t.Errorf("%s: %d packages, %v", p, len(ps), err)
		}
		t.Logf("%s: %d packages, first %s %s", p, len(ps), ps[0].Name, ps[0].Version)
		return nil
	})
}

func TestRPMEcosystem(t *testing.T) {
	for in, want := range map[string]string{
		"rhel 9.4":       "Red Hat:enterprise_linux:9",
		"rhel 8.10":      "Red Hat:enterprise_linux:8",
		"rhel 10.0":      "Red Hat:enterprise_linux:10.0",
		"rocky 9.3":      "Rocky Linux:9",
		"almalinux 8.9":  "AlmaLinux:8",
		"mageia 9":       "Mageia:9",
		"azurelinux 3.0": "Azure Linux:3",
		"fedora 40":      "",
		"centos 7":       "",
		"rhel ":          "",
	} {
		id, ver, _ := strings.Cut(in, " ")
		if got := rpmEcosystem(map[string]string{"ID": id, "VERSION_ID": ver}); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func TestCompareRPM(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// rpmvercmp cases from rpm's own test suite (tests/rpmvercmp.at)
		{"1.0", "1.0", 0}, {"1.0", "2.0", -1}, {"2.0.1", "2.0.1a", -1}, {"5.5p1", "5.5p2", -1},
		{"5.5p10", "5.5p1", 1}, {"10xyz", "10.1xyz", -1}, {"xyz10", "xyz10.1", -1}, {"xyz.4", "8", -1},
		{"5.5p1", "5.5.p1", 0}, {"5.0.1", "5.0.1", 0}, {"1.0aa", "1.0a", 1}, {"10", "9", 1},
		{"1.05", "1.5", 0}, {"6.0.rc1", "6.0", 1}, {"10b2", "10a1", 1}, {"1.0a", "1.0", 1},
		{"1.0~rc1", "1.0", -1}, {"1.0~rc1", "1.0~rc2", -1}, {"1.0~rc1~git123", "1.0~rc1", -1}, {"1.0~rc1", "1.0arc1", -1},
		{"1.0^", "1.0", 1}, {"1.0^git1", "1.0", 1}, {"1.0^git1", "1.01", -1}, {"1.0^20160101", "1.0.1", -1},
		{"1.0^20160101^git1", "1.0^20160101", 1}, {"1.0~rc1^git1", "1.0~rc1", 1}, {"1.0^git1~pre", "1.0^git1", -1},
		{"1.0^git1", "1.0^git2", -1}, {"1.0^git1", "1.0~rc1", 1},
		// epoch and release
		{"1:3.0.7-24.el9", "1:3.0.7-27.el9", -1}, {"3.0.7-27.el9", "1:3.0.7-24.el9", -1}, {"0:1.0-1", "1.0-1", 0},
		{"1:1.1.1k-6.el8_5", "1:1.1.1k-7.el8_6", -1}, {"2.28-251.el9_2.1", "2.28-251.el9_2", 1}, {"1.0", "1.0-5", 0},
	}
	for _, c := range cases {
		if got := compareRPM(c.a, c.b); got != c.want {
			t.Errorf("compareRPM(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := compareRPM(c.b, c.a); got != -c.want {
			t.Errorf("compareRPM(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
}

func FuzzRPMHeader(f *testing.F) {
	for _, b := range testBlobs() {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseRPMHeader(b) })
}

func FuzzRPMDB(f *testing.F) {
	f.Add(sqliteFixture(testBlobs()[:1]))
	f.Add(bdbFixture(testBlobs()[:1]))
	f.Add(ndbFixture(testBlobs()[:1]))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parseRPMDB("var/lib/rpm/Packages", b, "") })
}
