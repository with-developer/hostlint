package collect

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The rpm database of EL7 and EL8 (rpm 4.11 to 4.15) is a Berkeley DB hash
// file, Packages, whose key is the 4-byte (little-endian) number of a package
// and whose value is its rpm header. Like the SQLite reader, this one reads
// the file directly (ADR 0008): rpm and the Berkeley DB library write to the
// database's environment files even when asked to read. The file comes from
// the scanned host, so every offset is checked; a malformed file is an error,
// never a short list.
//
// Layout (db_page.h of Berkeley DB 5.3, hash version 9, little-endian):
//
//	page 0 (meta): magic 0x00061561 at 12, version at 16, page size at 20,
//	               page type at 25 (8), last page number at 32
//	every page:    pgno at 8, prev at 12, next at 16, entries at 20,
//	               hf_offset at 22, type at 25, 26-byte header, then an array
//	               of uint16 item offsets
//	hash page (13 or 2): items are key, value, key, value, ...; an item starts
//	               with a type byte: 1 = key/data, 3 = off-page (type, 3 unused
//	               bytes, pgno, total length)
//	overflow (7):  hf_offset bytes of data at 26, next page at 16

const (
	bdbHashMagic   = 0x00061561
	bdbHashVersion = 9
	bdbPageHeader  = 26

	bdbPageHash         = 13 // P_HASH
	bdbPageHashUnsorted = 2  // P_HASH_UNSORTED
	bdbPageOverflow     = 7  // P_OVERFLOW
	bdbPageHashMeta     = 8  // P_HASHMETA

	bdbItemKeyData = 1 // H_KEYDATA
	bdbItemOffPage = 3 // H_OFFPAGE
)

type bdbFile struct {
	data     []byte
	pageSize int
	pages    int // pages in the file that the metadata page counts
	// seen are the overflow pages read: a chain is a chain, so a page read
	// twice means a cycle or two values sharing a page, in a damaged file.
	seen map[int]bool
	// payload is the bytes of values read; the values of a valid file fit in
	// the file.
	payload int
}

// readRPMBDB returns the packages of an rpm Berkeley DB Packages file.
func readRPMBDB(data []byte) ([]rpmPackage, error) {
	db, err := openBDB(data)
	if err != nil {
		return nil, err
	}
	var pkgs []rpmPackage
	keys := map[uint32]bool{}
	var overflow []int
	counter := false
	for pgno := 1; pgno < len(data)/db.pageSize; pgno++ {
		page := db.page(pgno)
		entries := int(binary.LittleEndian.Uint16(page[20:]))
		switch t := page[25]; {
		case t == bdbPageOverflow:
			overflow = append(overflow, pgno)
			continue
		case t == 0 && entries == 0:
			continue // a free page, or one never used
		case t != bdbPageHash && t != bdbPageHashUnsorted:
			// Dropping a page of unknown kind, or a free page that still holds
			// items, would leave packages out of the list without an error.
			return nil, fmt.Errorf("%w: page %d has type %d and %d items", errMalformedDB, pgno, t, entries)
		case pgno >= db.pages:
			return nil, fmt.Errorf("%w: page %d is past the last page %d the metadata counts", errMalformedDB, pgno, db.pages-1)
		}
		if binary.LittleEndian.Uint32(page[8:]) != uint32(pgno) {
			return nil, fmt.Errorf("%w: page %d carries another page number", errMalformedDB, pgno)
		}
		if entries%2 != 0 || bdbPageHeader+2*entries > db.pageSize {
			return nil, fmt.Errorf("%w: page %d has %d items", errMalformedDB, pgno, entries)
		}
		for i := 0; i < entries; i += 2 {
			key, err := db.item(page, i)
			if err != nil {
				return nil, fmt.Errorf("page %d: %w", pgno, err)
			}
			if len(key) != 5 || key[0] != bdbItemKeyData {
				return nil, fmt.Errorf("%w: page %d has a key that is not a package number", errMalformedDB, pgno)
			}
			num := binary.LittleEndian.Uint32(key[1:])
			if keys[num] {
				return nil, fmt.Errorf("%w: package number %d appears twice", errMalformedDB, num)
			}
			keys[num] = true
			value, err := db.value(page, i+1)
			if err != nil {
				return nil, fmt.Errorf("page %d: %w", pgno, err)
			}
			if num == 0 {
				counter = true // rpm's counter of package numbers, not a package
				continue
			}
			pkg, err := parseRPMHeader(value)
			if err != nil {
				return nil, err
			}
			pkgs = append(pkgs, pkg)
		}
	}
	// Every overflow page belongs to a value read above: one that does not is
	// the value of a page that was dropped. rpm always keeps its counter.
	for _, pgno := range overflow {
		if !db.seen[pgno] {
			return nil, fmt.Errorf("%w: overflow page %d belongs to no package", errMalformedDB, pgno)
		}
	}
	if !counter {
		return nil, fmt.Errorf("%w: rpm's package counter is missing", errMalformedDB)
	}
	return pkgs, nil
}

func openBDB(data []byte) (*bdbFile, error) {
	if len(data) < 512 {
		return nil, fmt.Errorf("%w: too short for a Berkeley DB file", errMalformedDB)
	}
	switch magic := binary.LittleEndian.Uint32(data[12:]); {
	case magic == bdbHashMagic:
	case binary.BigEndian.Uint32(data[12:]) == bdbHashMagic:
		return nil, errors.New("a big-endian Berkeley DB rpm database is not supported")
	default:
		return nil, fmt.Errorf("%w: not a Berkeley DB hash file", errMalformedDB)
	}
	if v := binary.LittleEndian.Uint32(data[16:]); v != bdbHashVersion {
		return nil, fmt.Errorf("%w: Berkeley DB hash version %d is not supported (only %d)", errMalformedDB, v, bdbHashVersion)
	}
	ps := int(binary.LittleEndian.Uint32(data[20:]))
	if ps < 512 || ps > 65536 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d", errMalformedDB, ps)
	}
	if data[25] != bdbPageHashMeta {
		return nil, fmt.Errorf("%w: the first page is not a hash metadata page", errMalformedDB)
	}
	if len(data)%ps != 0 {
		return nil, fmt.Errorf("%w: the size is not a whole number of pages", errMalformedDB)
	}
	last := int64(binary.LittleEndian.Uint32(data[32:]))
	if last >= int64(len(data)/ps) {
		return nil, fmt.Errorf("%w: the last page %d is beyond the file", errMalformedDB, last)
	}
	return &bdbFile{data: data, pageSize: ps, pages: int(last) + 1, seen: map[int]bool{}}, nil
}

func (db *bdbFile) page(n int) []byte { return db.data[n*db.pageSize : (n+1)*db.pageSize] }

// item returns item i of a hash page, from its first byte (the type byte) up
// to the next item. Items are stored from the end of the page downwards, and
// the length of one is the distance to the one before it.
func (db *bdbFile) item(page []byte, i int) ([]byte, error) {
	off := int(binary.LittleEndian.Uint16(page[bdbPageHeader+2*i:]))
	end := db.pageSize
	if i > 0 {
		end = int(binary.LittleEndian.Uint16(page[bdbPageHeader+2*(i-1):]))
	}
	entries := int(binary.LittleEndian.Uint16(page[20:]))
	if off < bdbPageHeader+2*entries || off >= end || end > db.pageSize {
		return nil, fmt.Errorf("%w: item %d is outside its page", errMalformedDB, i)
	}
	return page[off:end], nil
}

// value returns the value of item i: inline, or read from its overflow pages.
func (db *bdbFile) value(page []byte, i int) ([]byte, error) {
	it, err := db.item(page, i)
	if err != nil {
		return nil, err
	}
	switch it[0] {
	case bdbItemKeyData:
		return it[1:], nil
	case bdbItemOffPage:
		if len(it) != 12 {
			return nil, fmt.Errorf("%w: an off-page item of %d bytes", errMalformedDB, len(it))
		}
		return db.overflow(binary.LittleEndian.Uint32(it[4:]), int64(binary.LittleEndian.Uint32(it[8:])))
	}
	return nil, fmt.Errorf("%w: item type %d (duplicates are not used by rpm)", errMalformedDB, it[0])
}

// overflow reads a value of total bytes from the chain of overflow pages that
// starts at pgno.
func (db *bdbFile) overflow(pgno uint32, total int64) ([]byte, error) {
	if total < 1 || total > maxRPMHeader || db.payload+int(total) > 2*len(db.data) {
		return nil, fmt.Errorf("%w: a value of %d bytes", errMalformedDB, total)
	}
	db.payload += int(total)
	out := make([]byte, 0, total)
	for pgno != 0 {
		if int(pgno) >= db.pages || db.seen[int(pgno)] {
			return nil, fmt.Errorf("%w: overflow page %d", errMalformedDB, pgno)
		}
		db.seen[int(pgno)] = true
		page := db.page(int(pgno))
		if page[25] != bdbPageOverflow || binary.LittleEndian.Uint32(page[8:]) != pgno {
			return nil, fmt.Errorf("%w: page %d is not an overflow page", errMalformedDB, pgno)
		}
		n := int(binary.LittleEndian.Uint16(page[22:]))
		if n > db.pageSize-bdbPageHeader || int64(len(out))+int64(n) > total {
			return nil, fmt.Errorf("%w: overflow page %d holds %d bytes", errMalformedDB, pgno, n)
		}
		out = append(out, page[bdbPageHeader:bdbPageHeader+n]...)
		pgno = binary.LittleEndian.Uint32(page[16:])
	}
	if int64(len(out)) != total {
		return nil, fmt.Errorf("%w: a value of %d bytes ends after %d", errMalformedDB, total, len(out))
	}
	return out, nil
}
