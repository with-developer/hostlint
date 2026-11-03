package collect

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// The rpm database of EL9 and later (rpm 4.16+) is SQLite: a table Packages
// (hnum INTEGER PRIMARY KEY, blob BLOB) whose blobs are rpm headers. hostlint
// reads the file directly: running rpm, or a SQLite library in read-write
// mode, would write to the host (ADR 0008). The file comes from the scanned
// host, so every offset is checked; a malformed file is an error, never a
// short list.

var errMalformedDB = errors.New("malformed rpm database")

// rpmPackage is what hostlint keeps of an rpm header.
type rpmPackage struct {
	name, version, release, arch string
	epoch                        int64
}

// readRPMSQLite returns the packages of an rpm SQLite database.
func readRPMSQLite(data []byte) ([]rpmPackage, error) {
	db, err := openSQLite(data)
	if err != nil {
		return nil, err
	}
	root, err := db.tableRoot("Packages")
	if err != nil {
		return nil, err
	}
	var pkgs []rpmPackage
	err = db.tableRows(root, func(record []byte) error {
		cols, err := recordColumns(record)
		if err != nil {
			return err
		}
		if len(cols) < 2 || cols[1].kind != colBlob {
			return fmt.Errorf("%w: a Packages row has no header blob", errMalformedDB)
		}
		pkg, err := parseRPMHeader(cols[1].data)
		if err != nil {
			return err
		}
		pkgs = append(pkgs, pkg)
		return nil
	})
	return pkgs, err
}

// --- SQLite file format (https://www.sqlite.org/fileformat.html) ---------------

type sqliteDB struct {
	data     []byte
	pageSize int
	usable   int
	pages    int
	visits   int // pages read, against a cycle in a corrupt file
}

func openSQLite(data []byte) (*sqliteDB, error) {
	if len(data) < 100 || !bytes.Equal(data[:16], []byte("SQLite format 3\x00")) {
		return nil, fmt.Errorf("%w: not a SQLite file", errMalformedDB)
	}
	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d", errMalformedDB, pageSize)
	}
	usable := pageSize - int(data[20])
	if usable < 480 {
		return nil, fmt.Errorf("%w: usable page size %d", errMalformedDB, usable)
	}
	return &sqliteDB{data: data, pageSize: pageSize, usable: usable, pages: len(data) / pageSize}, nil
}

// page returns page n (1-based) and the offset of its b-tree header.
func (db *sqliteDB) page(n uint32) ([]byte, int, error) {
	db.visits++
	if n < 1 || int64(n) > int64(db.pages) || db.visits > 4*db.pages+16 {
		return nil, 0, fmt.Errorf("%w: page %d", errMalformedDB, n)
	}
	off := int(n-1) * db.pageSize
	header := 0
	if n == 1 {
		header = 100
	}
	return db.data[off : off+db.pageSize], header, nil
}

// tableRoot finds a table's root page in sqlite_schema (page 1).
func (db *sqliteDB) tableRoot(name string) (uint32, error) {
	var root uint32
	err := db.tableRows(1, func(record []byte) error {
		cols, err := recordColumns(record)
		if err != nil {
			return err
		}
		// type, name, tbl_name, rootpage, sql
		if len(cols) >= 4 && string(cols[0].data) == "table" && string(cols[1].data) == name && cols[3].kind == colInt {
			if cols[3].i < 1 || cols[3].i > int64(db.pages) || cols[3].i > 1<<31 {
				return fmt.Errorf("%w: root page %d", errMalformedDB, cols[3].i)
			}
			root = uint32(cols[3].i) //nolint:gosec // G115: checked against the page count above
		}
		return nil
	})
	if err == nil && root == 0 {
		err = fmt.Errorf("%w: no %s table", errMalformedDB, name)
	}
	return root, err
}

// tableRows calls fn with the payload of every row of the table b-tree at
// root, in rowid order.
func (db *sqliteDB) tableRows(root uint32, fn func(record []byte) error) error {
	return db.walk(root, 0, fn)
}

func (db *sqliteDB) walk(n uint32, depth int, fn func([]byte) error) error {
	if depth > 32 {
		return fmt.Errorf("%w: b-tree too deep", errMalformedDB)
	}
	p, h, err := db.page(n)
	if err != nil {
		return err
	}
	if h+12 > len(p) {
		return fmt.Errorf("%w: page %d too short", errMalformedDB, n)
	}
	cells := int(binary.BigEndian.Uint16(p[h+3:]))
	switch p[h] {
	case 0x0d: // table leaf
		for i := range cells {
			ptr := h + 8 + 2*i
			if ptr+2 > len(p) {
				return fmt.Errorf("%w: cell pointers past page %d", errMalformedDB, n)
			}
			payload, err := db.leafPayload(p, int(binary.BigEndian.Uint16(p[ptr:])))
			if err != nil {
				return err
			}
			if err := fn(payload); err != nil {
				return err
			}
		}
		return nil
	case 0x05: // table interior
		for i := range cells {
			ptr := h + 12 + 2*i
			if ptr+2 > len(p) {
				return fmt.Errorf("%w: cell pointers past page %d", errMalformedDB, n)
			}
			off := int(binary.BigEndian.Uint16(p[ptr:]))
			if off+4 > len(p) {
				return fmt.Errorf("%w: cell past page %d", errMalformedDB, n)
			}
			if err := db.walk(binary.BigEndian.Uint32(p[off:]), depth+1, fn); err != nil {
				return err
			}
		}
		return db.walk(binary.BigEndian.Uint32(p[h+8:]), depth+1, fn)
	}
	return fmt.Errorf("%w: page %d is not a table b-tree page (type %d)", errMalformedDB, n, p[h])
}

// leafPayload returns the payload of the table leaf cell at off, following
// its overflow pages.
func (db *sqliteDB) leafPayload(p []byte, off int) ([]byte, error) {
	if off <= 0 || off >= len(p) {
		return nil, fmt.Errorf("%w: cell offset %d", errMalformedDB, off)
	}
	size, n := sqliteVarint(p[off:])
	if n == 0 || size < 0 || size > int64(len(db.data)) {
		return nil, fmt.Errorf("%w: payload size", errMalformedDB)
	}
	off += n
	_, n = sqliteVarint(p[off:]) // rowid
	if n == 0 {
		return nil, fmt.Errorf("%w: rowid", errMalformedDB)
	}
	off += n
	total := int(size)
	local := db.localSize(total)
	if off+local > len(p) {
		return nil, fmt.Errorf("%w: payload past page", errMalformedDB)
	}
	payload := append(make([]byte, 0, total), p[off:off+local]...)
	if local == total {
		return payload, nil
	}
	if off+local+4 > len(p) {
		return nil, fmt.Errorf("%w: overflow pointer past page", errMalformedDB)
	}
	next := binary.BigEndian.Uint32(p[off+local:])
	for len(payload) < total {
		op, _, err := db.page(next)
		if err != nil {
			return nil, err
		}
		chunk := min(total-len(payload), db.usable-4)
		payload = append(payload, op[4:4+chunk]...)
		next = binary.BigEndian.Uint32(op)
	}
	return payload, nil
}

// localSize is how much of a table leaf payload is stored on its page.
func (db *sqliteDB) localSize(total int) int {
	u := db.usable
	maxLocal := u - 35
	if total <= maxLocal {
		return total
	}
	minLocal := (u-12)*32/255 - 23
	k := minLocal + (total-minLocal)%(u-4)
	if k <= maxLocal {
		return k
	}
	return minLocal
}

// sqliteVarint decodes a SQLite varint; n is 0 when b is too short.
func sqliteVarint(b []byte) (int64, int) {
	var v uint64
	for i := range min(len(b), 9) {
		if i == 8 {
			v = v<<8 | uint64(b[i])
			return int64(v), 9 //nolint:gosec // G115: a 64-bit varint is two's complement by definition
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i] < 0x80 {
			return int64(v), i + 1 //nolint:gosec // G115: at most 56 bits here
		}
	}
	return 0, 0
}

type colKind int

const (
	colNull colKind = iota
	colInt
	colBlob
	colText
	colOther
)

type column struct {
	kind colKind
	i    int64
	data []byte
}

// recordColumns decodes a record: a header of serial types, then values.
func recordColumns(rec []byte) ([]column, error) {
	hsize, n := sqliteVarint(rec)
	if n == 0 || hsize < int64(n) || hsize > int64(len(rec)) {
		return nil, fmt.Errorf("%w: record header", errMalformedDB)
	}
	var cols []column
	body := int(hsize)
	for pos := n; pos < int(hsize); {
		st, m := sqliteVarint(rec[pos:int(hsize)])
		if m == 0 || st < 0 {
			return nil, fmt.Errorf("%w: serial type", errMalformedDB)
		}
		pos += m
		size, kind := serialSize(st)
		if size < 0 || body+size > len(rec) {
			return nil, fmt.Errorf("%w: column past record", errMalformedDB)
		}
		c := column{kind: kind, data: rec[body : body+size]}
		if kind == colInt {
			c.i = bigEndianInt(c.data, st)
		}
		cols = append(cols, c)
		body += size
	}
	return cols, nil
}

// serialSize returns the size and kind of a value of serial type st.
func serialSize(st int64) (int, colKind) {
	switch {
	case st == 0:
		return 0, colNull
	case st >= 1 && st <= 4:
		return int(st), colInt
	case st == 5:
		return 6, colInt
	case st == 6:
		return 8, colInt
	case st == 7:
		return 8, colOther
	case st == 8 || st == 9:
		return 0, colInt
	case st >= 12 && st%2 == 0:
		return int((st - 12) / 2), colBlob
	case st >= 13:
		return int((st - 13) / 2), colText
	}
	return -1, colOther
}

func bigEndianInt(b []byte, st int64) int64 {
	switch st {
	case 8:
		return 0
	case 9:
		return 1
	}
	var v int64
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	if len(b) > 0 && len(b) < 8 && b[0]&0x80 != 0 {
		v -= 1 << (8 * len(b)) // sign-extend
	}
	return v
}

// --- rpm headers -----------------------------------------------------------------

// Header tags and types (rpmtag.h).
const (
	rpmTagName    = 1000
	rpmTagVersion = 1001
	rpmTagRelease = 1002
	rpmTagEpoch   = 1003
	rpmTagArch    = 1022

	rpmTypeInt32  = 4
	rpmTypeString = 6
)

// parseRPMHeader reads an exported rpm header: the index entry count and
// data size, index entries (tag, type, offset, count), then the data.
func parseRPMHeader(b []byte) (rpmPackage, error) {
	if len(b) < 8 {
		return rpmPackage{}, fmt.Errorf("%w: header too short", errMalformedDB)
	}
	il := int64(binary.BigEndian.Uint32(b[0:4]))
	dl := int64(binary.BigEndian.Uint32(b[4:8]))
	if il < 1 || il > 65536 || 8+il*16+dl > int64(len(b)) {
		return rpmPackage{}, fmt.Errorf("%w: header sizes", errMalformedDB)
	}
	index := b[8 : 8+il*16]
	store := b[8+il*16 : 8+il*16+dl]
	var pkg rpmPackage
	for i := range int(il) {
		e := index[i*16 : i*16+16]
		tag := binary.BigEndian.Uint32(e[0:4])
		typ := binary.BigEndian.Uint32(e[4:8])
		off := int64(binary.BigEndian.Uint32(e[8:12]))
		count := binary.BigEndian.Uint32(e[12:16])
		if off >= int64(len(store)) {
			continue
		}
		switch {
		case typ == rpmTypeString && (tag == rpmTagName || tag == rpmTagVersion || tag == rpmTagRelease || tag == rpmTagArch):
			s, ok := cString(store[off:])
			if !ok {
				return rpmPackage{}, fmt.Errorf("%w: unterminated string", errMalformedDB)
			}
			switch tag {
			case rpmTagName:
				pkg.name = s
			case rpmTagVersion:
				pkg.version = s
			case rpmTagRelease:
				pkg.release = s
			case rpmTagArch:
				pkg.arch = s
			}
		case tag == rpmTagEpoch && typ == rpmTypeInt32 && count >= 1 && off+4 <= int64(len(store)):
			pkg.epoch = int64(binary.BigEndian.Uint32(store[off:]))
		}
	}
	if pkg.name == "" {
		return rpmPackage{}, fmt.Errorf("%w: header without a name", errMalformedDB)
	}
	return pkg, nil
}

func cString(b []byte) (string, bool) {
	end := bytes.IndexByte(b[:min(len(b), 4096)], 0)
	if end < 0 {
		return "", false
	}
	return string(b[:end]), true
}

// fullVersion is [epoch:]version-release, as for dpkg's versions.
func (p rpmPackage) fullVersion() string {
	v := p.version + "-" + p.release
	if p.epoch != 0 {
		v = strconv.FormatInt(p.epoch, 10) + ":" + v
	}
	return v
}
