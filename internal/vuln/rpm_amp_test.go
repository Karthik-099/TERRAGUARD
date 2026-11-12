package vuln

import (
	"encoding/binary"
	"testing"
)

func TestBDBSharedOverflowIsCapped(t *testing.T) {
	const ps = 4096
	const chain = 128
	npages := 1 + chain + 1
	b := make([]byte, npages*ps)
	le := binary.LittleEndian
	le.PutUint32(b[12:], bdbHashMagic)
	le.PutUint32(b[20:], ps)
	le.PutUint32(b[32:], uint32(npages-1))
	for i := 1; i <= chain; i++ {
		pg := b[i*ps : (i+1)*ps]
		pg[25] = bdbPageOverflow
		le.PutUint16(pg[22:], ps-26)
		if i < chain {
			le.PutUint32(pg[16:], uint32(i+1))
		}
	}
	total := uint32(chain * (ps - 26))
	hp := b[(chain+1)*ps:]
	hp[25] = bdbPageHash
	entries := 1980
	le.PutUint16(hp[20:], uint16(entries))
	item := 4000
	for i := 0; i < entries; i++ {
		le.PutUint16(hp[26+2*i:], uint16(item))
	}
	hp[item] = bdbOffPage
	le.PutUint32(hp[item+4:], 1)
	le.PutUint32(hp[item+8:], total)
	// many entries sharing one overflow chain must be refused, not copied again and again
	if _, err := bdbHashValues(b); err != errRPMCorrupt {
		t.Fatalf("want errRPMCorrupt, got %v", err)
	}
}
