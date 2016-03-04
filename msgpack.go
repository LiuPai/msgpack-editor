package msgpack

//go:generate stringer -type=MsgPackFormat

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

/*
Limitation https://github.com/msgpack/msgpack/blob/master/spec.md#limitation
a value of an Integer object is limited from -(2^63) upto (2^64)-1
maximum length of a Binary object is (2^32)-1
maximum byte size of a String object is (2^32)-1
String objects may contain invalid byte sequence and the behavior of a
deserializer depends on the actual implementation when it received invalid byte
 sequence
    Deserializers should provide functionality to get the original byte array so
    that applications can decide how to handle the object
maximum number of elements of an Array object is (2^32)-1
maximum number of key-value associations of a Map object is (2^32)-1
*/
// Message pack limits
const (
	MaxInt               = 1<<63 - 1
	MinInt               = -1 << 63
	MaxBinaryLength      = 1<<31 - 1
	MaxStringBytesLength = 1<<31 - 1
	MaxArrayLength       = 1<<31 - 1
	MaxMapLengtth        = 1<<31 - 1
)

/*
Extension https://github.com/msgpack/msgpack/blob/master/spec.md#extension-type
MessagePack allows applications to define application-specific types using the
Extension type. Extension type consists of an integer and a byte array where the
 integer represents a kind of types and the byte array represents data.

Applications can assign 0 to 127 to store application-specific type information.

MessagePack reserves -1 to -128 for future extension to add predefined types
which will be described in separated documents.
```
[0, 127]: application-specific types
[-128, -1]: reserved for predefined types
```
*/
// Extension type application-specific type information
const (
	MinExtTypeID = 0
	MaxExtTypeID = 1<<7 - 1
)

/*
Format https://github.com/msgpack/msgpack/blob/master/spec.md#overview
Overview
|format name | first byte (in binary) | first byte (in hex)
positive fixint | 0xxxxxxx | 0x00 - 0x7f
fixmap | 1000xxxx | 0x80 - 0x8f
fixarray | 1001xxxx | 0x90 - 0x9f
fixstr | 101xxxxx | 0xa0 - 0xbf
nil | 11000000 | 0xc0
(never used) | 11000001 | 0xc1
false | 11000010 | 0xc2
true | 11000011 | 0xc3
bin 8 | 11000100 | 0xc4
bin 16 | 11000101 | 0xc5
bin 32 | 11000110 | 0xc6
ext 8 | 11000111 | 0xc7
ext 16 | 11001000 | 0xc8
ext 32 | 11001001 | 0xc9
float 32 | 11001010 | 0xca
float 64 | 11001011 | 0xcb
uint 8 | 11001100 | 0xcc
uint 16 | 11001101 | 0xcd
uint 32 | 11001110 | 0xce
uint 64 | 11001111 | 0xcf
int 8 | 11010000 | 0xd0
int 16 | 11010001 | 0xd1
int 32 | 11010010 | 0xd2
int 64 | 11010011 | 0xd3
fixext 1 | 11010100 | 0xd4
fixext 2 | 11010101 | 0xd5
fixext 4 | 11010110 | 0xd6
fixext 8 | 11010111 | 0xd7
fixext 16 | 11011000 | 0xd8
str 8 | 11011001 | 0xd9
str 16 | 11011010 | 0xda
str 32 | 11011011 | 0xdb
array 16 | 11011100 | 0xdc
array 32 | 11011101 | 0xdd
map 16 | 11011110 | 0xde
map 32 | 11011111 | 0xdf
negative fixint | 111xxxxx | 0xe0 - 0xff
*/

// Format Formats
type Format byte

// Mask Formats
const (
	NotExist           Format = 0xFF
	PostiveFixIntMask  Format = 0        // (byte) >> 7 == PostiveFixIntMask
	FixMapMask         Format = 1 << 3   // (byte) >> 4 == FixMapMask
	FixArrayMask       Format = 1<<3 + 1 // (byte) >> 4 == FixArrayMask
	FixStrMask         Format = 1<<2 + 1 // (byte) >> 5 == FixStrMask
	NegativeFixIntMask Format = 1<<2 + 3 // (byte) >> 5 == NegativeFixIntMask
)

// Split Formats
const (
	Nil Format = iota + 0xC0
	NeverUsed
	False
	True
	Bin8
	Bin16
	Bin32
	Ext8
	Ext16
	Ext32
	Float32
	Float64
	UInt8
	UInt16
	UInt32
	UInt64
	Int8
	Int16
	Int32
	Int64
	FixExt1
	FixExt2
	FixExt4
	FixExt8
	FixExt16
	Str8
	Str16
	Str32
	Array16
	Array32
	Map16
	Map32
	End
)

// ValueType
const (
	Default = iota
	Key
	Value
)

// Max Lengths
const (
	FixStrMaxLength   = 1<<5 - 1
	Str8MaxLength     = 1<<8 - 1
	Str16MaxLength    = 1<<16 - 1
	Str32MaxLength    = 1<<32 - 1
	Bin8MaxLength     = 1<<8 - 1
	Bin16MaxLength    = 1<<16 - 1
	Bin32MaxLength    = 1<<32 - 1
	FixArrayMaxLength = 1<<4 - 1
	Array16MaxLength  = 1<<16 - 1
	Array32MaxLength  = 1<<32 - 1
	FixMapMaxLength   = 1<<4 - 1
	Map16MaxLength    = 1<<16 - 1
	Map32MaxLength    = 1<<32 - 1
	Ext8MaxLength     = 1<<8 - 1
	Ext16MaxLength    = 1<<16 - 1
	Ext32MaxLength    = 1<<32 - 1
)

// node path spliter
const (
	PathSpliter = "|=|"
)

// MsgPack node tree
type MsgPack struct {
	data []byte
	r    *bytes.Reader
	Root *MsgNode
}

// ExtNode messagepack ext type struct
type ExtNode struct {
}

// MsgNode tree node
type MsgNode struct {
	Parent      *MsgNode `json:"-"`
	Format      Format
	FormatName  string
	Length      uint64
	Value       interface{}
	Array       []*MsgNode
	Map         map[*MsgNode]*MsgNode
	Ext         *ExtNode
	LeadByte    byte
	LengthBytes []byte
	ValueBytes  []byte
}

// NewMsgPack creat messagepack tree with messagepack data
func NewMsgPack(d []byte) *MsgPack {
	m := &MsgPack{
		data: d,
	}
	m.r = bytes.NewReader(m.data)
	start := time.Now()
	m.Root = m.parseNode(m.r, nil)
	end := time.Now()
	fmt.Printf("MessagePack Tree Parse time: %vns\n", end.UnixNano()-start.UnixNano())
	return m
}

// Load Update messagepack data
func (m *MsgPack) Load(d []byte) {
	m.data = d
	m.r = bytes.NewReader(m.data)
	m.Root = m.parseNode(m.r, nil)
}

func (m *MsgPack) DecodeToJSON() string {
	return ""
}

func lengthBytes(format Format, length uint64) []byte {
	var (
		buf []byte
		err error
	)
	w := bytes.NewBuffer(buf)
	switch format {
	case Nil, True, False:
	case Bin8, Ext8, Str8:
		err = binary.Write(w, binary.BigEndian, uint8(length))
	case Bin16, Ext16, Str16, Array16, Map16:
		err = binary.Write(w, binary.BigEndian, uint16(length))
	case Bin32, Ext32, Str32, Array32, Map32:
		err = binary.Write(w, binary.BigEndian, uint32(length))
	}
	if err != nil {
		panic(err)
	}
	return w.Bytes()
}

func valueBytes(format Format, length uint64, value interface{}) []byte {
	var (
		buf []byte
		err error
	)
	w := bytes.NewBuffer(buf)
	switch format {
	case Nil, True, False, PostiveFixIntMask, NegativeFixIntMask:
	case Int8:
		err = binary.Write(w, binary.BigEndian, int8(value.(int64)))
	case UInt8:
		err = binary.Write(w, binary.BigEndian, uint8(value.(uint64)))
	case Int16:
		err = binary.Write(w, binary.BigEndian, int16(value.(int64)))
	case UInt16:
		err = binary.Write(w, binary.BigEndian, uint16(value.(uint64)))
	case Int32:
		err = binary.Write(w, binary.BigEndian, int32(value.(int64)))
	case UInt32:
		err = binary.Write(w, binary.BigEndian, uint32(value.(uint64)))
	case Float32:
		err = binary.Write(w, binary.BigEndian, float32(value.(float64)))
	case Int64:
		err = binary.Write(w, binary.BigEndian, value.(int64))
	case UInt64:
		err = binary.Write(w, binary.BigEndian, value.(uint64))
	case Float64:
		err = binary.Write(w, binary.BigEndian, value.(float64))
	case FixStrMask, Str16, Str32:
		err = binary.Write(w, binary.BigEndian, []byte(value.(string)))
	case Bin8, Ext8:
		err = binary.Write(w, binary.BigEndian, value.([]byte))
	case Bin16, Ext16:
		err = binary.Write(w, binary.BigEndian, value.([]byte))
	case Bin32, Ext32:
		err = binary.Write(w, binary.BigEndian, value.([]byte))
	}
	if err != nil {
		panic(err)
	}
	return w.Bytes()
}

func updateLength(Type Format, length uint64) (leadByte byte, lengthBytes []byte) {
	w := bytes.NewBuffer(make([]byte, 0, 64))
	var err error
	switch Type {
	case FixStrMask, Str8, Str16, Str32:
		switch true {
		case length > Str32MaxLength:
			panic(fmt.Sprintf("String length[%d] too long, need less than [%d]",
				length, Str32MaxLength))
		case length > Str16MaxLength:
			leadByte = byte(Str32)
			err = binary.Write(w, binary.BigEndian, uint32(length))
			lengthBytes = w.Bytes()
		case length > Str8MaxLength:
			leadByte = byte(Str16)
			err = binary.Write(w, binary.BigEndian, uint16(length))
			lengthBytes = w.Bytes()
		case length > FixStrMaxLength:
			leadByte = byte(Str8)
			err = binary.Write(w, binary.BigEndian, uint8(length))
			lengthBytes = w.Bytes()
		case length > 0:
			leadByte = byte(uint8(FixStrMask<<5) | uint8(length))
		default:
			panic(fmt.Sprintf("String length[%d] underflow!", length))
		}
	case Bin8, Bin16, Bin32:
		switch true {
		case length > Bin32MaxLength:
			panic(fmt.Sprintf("Bin length[%d] too long, need less than [%d]",
				length, Bin32MaxLength))
		case length > Bin16MaxLength:
			leadByte = byte(Bin32)
			err = binary.Write(w, binary.BigEndian, uint32(length))
			lengthBytes = w.Bytes()
		case length > Bin8MaxLength:
			leadByte = byte(Bin16)
			err = binary.Write(w, binary.BigEndian, uint16(length))
			lengthBytes = w.Bytes()
		case length > 0:
			leadByte = byte(Bin8)
			err = binary.Write(w, binary.BigEndian, uint8(length))
			lengthBytes = w.Bytes()
		default:
			panic(fmt.Sprintf("Bin length[%d] underflow!", length))
		}
	case Ext8, Ext16, Ext32:
		switch true {
		case length > Ext32MaxLength:
			panic(fmt.Sprintf("Ext length[%d] too long, need less than [%d]",
				length, Ext32MaxLength))
		case length > Ext16MaxLength:
			leadByte = byte(Ext32)
			err = binary.Write(w, binary.BigEndian, uint32(length))
			lengthBytes = w.Bytes()
		case length > Ext8MaxLength:
			leadByte = byte(Ext16)
			err = binary.Write(w, binary.BigEndian, uint16(length))
			lengthBytes = w.Bytes()
		case length > 0:
			leadByte = byte(Ext8)
			err = binary.Write(w, binary.BigEndian, uint8(length))
			lengthBytes = w.Bytes()
		default:
			panic(fmt.Sprintf("Ext length[%d] underflow!", length))
		}
	case FixArrayMask, Array16, Array32:
		switch true {
		case length > Array32MaxLength:
			panic(fmt.Sprintf("Arraying length[%d] too long, need less than [%d]",
				length, Array32MaxLength))
		case length > Array16MaxLength:
			leadByte = byte(Array32)
			err = binary.Write(w, binary.BigEndian, uint32(length))
			lengthBytes = w.Bytes()
		case length > FixArrayMaxLength:
			leadByte = byte(Array16)
			err = binary.Write(w, binary.BigEndian, uint16(length))
			lengthBytes = w.Bytes()
		case length > 0:
			leadByte = byte(uint8(FixArrayMask<<4) | uint8(length))
		default:
			panic(fmt.Sprintf("Arraying length[%d] underflow!", length))
		}
	case FixMapMask, Map16, Map32:
		switch true {
		case length > Map32MaxLength:
			panic(fmt.Sprintf("Map length[%d] too long, need less than [%d]",
				length, Map32MaxLength))
		case length > Map16MaxLength:
			leadByte = byte(Map32)
			err = binary.Write(w, binary.BigEndian, uint32(length))
			lengthBytes = w.Bytes()
		case length > FixMapMaxLength:
			leadByte = byte(Map16)
			err = binary.Write(w, binary.BigEndian, uint16(length))
			lengthBytes = w.Bytes()
		case length > 0:
			leadByte = byte(uint8(FixMapMask<<4) | uint8(length))
		default:
			panic(fmt.Sprintf("Map length[%d] underflow!", length))
		}
	}
	if err != nil {
		panic(err)
	}
	return
}

func updateValue() {
}

func (m *MsgPack) parseNode(r *bytes.Reader, parent *MsgNode) *MsgNode {
	node := new(MsgNode)
	node.Parent = parent
	err := binary.Read(r, binary.BigEndian, &node.LeadByte)
	if err != nil {
		panic(err)
	}
	node.Format, node.Length = getType(r, node.LeadByte)
	node.FormatName = node.Format.String()
	node.LengthBytes = lengthBytes(node.Format, node.Length)
	switch node.Format {
	case FixArrayMask, Array16, Array32: // Parent node
		node.Array = make([]*MsgNode, node.Length)
		for i := uint64(0); i < node.Length; i++ {
			node.Array[i] = m.parseNode(r, node)
		}
	case FixMapMask, Map16, Map32: // Parent node
		node.Map = make(map[*MsgNode]*MsgNode, node.Length)
		for i := uint64(0); i < node.Length; i++ {
			key := m.parseNode(r, node)
			value := m.parseNode(r, node)
			node.Map[key] = value
		}
	default: // Value node
		node.Value = getValue(r, node.LeadByte, node.Format, node.Length)
		node.ValueBytes = valueBytes(node.Format, node.Length, node.Value)
	}
	return node
}

// WriteTree Write messagepack data to w
func (m *MsgPack) WriteTree(w *bytes.Buffer, node *MsgNode) {
	err := w.WriteByte(node.LeadByte)
	if err != nil {
		panic(err)
	}
	_, err = w.Write(node.LengthBytes)
	if err != nil {
		panic(err)
	}
	switch node.Format {
	case FixArrayMask, Array16, Array32: // Parent node
		for _, n := range node.Array {
			m.WriteTree(w, n)
		}
	case FixMapMask, Map16, Map32: // Parent node
		for k, v := range node.Map {
			m.WriteTree(w, k)
			m.WriteTree(w, v)
		}
	default: // Value node
		_, err = w.Write(node.ValueBytes)
		if err != nil {
			panic(err)
		}
	}
}

// NodeBin get select node's messagepack data
func (m *MsgPack) NodeBin(node *MsgNode) []byte {
	w := bytes.NewBuffer(make([]byte, 0, 4096))
	m.WriteTree(w, node)
	return w.Bytes()
}

func dump(r *bytes.Reader, level int, tp int) {
	var t byte
	err := binary.Read(r, binary.BigEndian, &t)
	if err != nil {
		if err == io.EOF {
			return
		}
		panic(err)
	}
	format, length := getType(r, t)
	for i := 0; i < level; i++ {
		fmt.Print("   ")
	}
	switch tp {
	case Key:
		fmt.Print("Key:   ")
	case Value:
		fmt.Print("Value: ")
	default:
		if tp < 0 {
			fmt.Printf("Index: %d ", -tp)
		}
	}

	fmt.Printf("Type: %20s, length: %5d value: ", format.String(), length)
	// read value
	switch format {
	case FixArrayMask, Array16, Array32:
		fmt.Print("\n")
		for i := uint64(0); i < length; i++ {
			dump(r, level+1, int(-i))
		}
	case FixMapMask, Map16, Map32:
		fmt.Print("\n")
		for i := uint64(0); i < length; i++ {
			dump(r, level+1, Key)
			dump(r, level+1, Value)
		}
	default:
		value := getValue(r, t, format, length)
		switch i := value.(type) {
		case int64, uint64:
			fmt.Printf("%d\n", i)
		case float64:
			fmt.Printf("%f\n", i)
		case string:
			fmt.Printf("%s\n", i)
		case bool:
			fmt.Printf("%v\n", i)
		default:
			fmt.Printf("%#v\n", i)
		}

	}
}

// Dump desplay messagepack tree struct
func (m *MsgPack) Dump() {
	_, err := m.r.Seek(0, 0)
	if err != nil {
		panic(err)
	}
	dump(m.r, 0, Default)
}

func dumpPath(r *bytes.Reader, level int, tg int, paths []string, skip bool) {
	t, err := r.ReadByte()
	if err != nil {
		if err == io.EOF {
			return
		}
		panic(err)
	}
	format, length := getType(r, t)
	switch format {
	case FixMapMask, Map16, Map32:
		for i := uint64(0); i < length; i++ {
			_ = binary.Read(r, binary.BigEndian, &t)
			keyFormat, keyLength := getType(r, t)
			keyValue := getValue(r, t, keyFormat, keyLength)
			if skip {
				dumpPath(r, 0, tg, paths, true)
				continue
			}
			var key string
			switch k := keyValue.(type) {
			case int64, uint64:
				key = fmt.Sprintf("%d", k)
			case float64:
				key = fmt.Sprintf("%f", k)
			case string:
				key = fmt.Sprintf("%s", k)
			case bool:
				key = fmt.Sprintf("%v", k)
			default:
				key = fmt.Sprintf("%v", k)
			}
			if key != paths[level] {
				dumpPath(r, 0, tg, paths, true)
				continue
			} else if level == len(paths)-1 {
				dump(r, 0, tg)
				break
			} else {
				dumpPath(r, level+1, tg, paths, false)
			}
		}
	case FixArrayMask, Array16, Array32:
		for i := uint64(0); i < length; i++ {
			dumpPath(r, 0, tg, paths, true)
		}
	default:
		_ = getValue(r, t, format, length)
		return
	}
}

// DumpAbsNode display select node struct
func (m *MsgPack) DumpAbsNode(path string) {
	_, err := m.r.Seek(0, 0)
	if err != nil {
		panic(err)
	}
	paths := strings.Split(path, PathSpliter)
	dumpPath(m.r, 0, Default, paths, false)
}

func (m *MsgPack) searchNode(node *MsgNode, level int, paths []string) (key *MsgNode, value *MsgNode) {
	if paths[level] == "" {
		return nil, node
	}
	switch node.Format {
	case FixMapMask, Map16, Map32:
		for k, v := range node.Map {
			if k.Value == paths[level] {
				if level == len(paths)-1 {
					return k, v
				}
				return m.searchNode(v, level+1, paths)
			}
		}
	}
	return nil, nil
}

// GetNode get select node from messagepack tree struct
func (m *MsgPack) GetNode(path string) (key, value *MsgNode) {
	paths := strings.Split(path, PathSpliter)
	key, value = m.searchNode(m.Root, 0, paths)
	return
}

// RemoveNode remove select node from messagepack tree struct
func (m *MsgPack) RemoveNode(path string) {
	paths := strings.Split(path, PathSpliter)
	key, value := m.searchNode(m.Root, 0, paths)
	if key == nil || value == nil {
		panic(fmt.Sprintf("Path[%s] not found", path))
	}
	parent := value.Parent
	if parent == nil {
		return
	}
	// update parent length
	parent.Length--
	parent.LeadByte, parent.LengthBytes = updateLength(parent.Format, parent.Length)
	delete(parent.Map, key)
	return
}

// AddNode add node to select path
func (m *MsgPack) AddNode(path string, key, value *MsgNode) {
	if value == nil {
		panic("Value is nil")
	}
	paths := strings.Split(path, PathSpliter)
	_, parent := m.searchNode(m.Root, 0, paths)
	if parent == nil {
		panic(fmt.Sprintf("Path[%s] not found", path))
	}
	// updaet parent length
	parent.Length++
	parent.LeadByte, parent.LengthBytes = updateLength(parent.Format, parent.Length)
	switch parent.Format {
	case FixMapMask, Map16, Map32:
		if key == nil {
			panic("Map Key is nil")
		}
		parent.Map[key] = value
		key.Parent = parent
		value.Parent = parent
	case FixArrayMask, Array16, Array32:
		parent.Array = append(parent.Array, value)
		value.Parent = parent
	default:
		panic(fmt.Sprintf("Parent Format[%s] not support add child node",
			parent.FormatName))
	}
}

func getValue(r *bytes.Reader, t byte, format Format, length uint64) interface{} {
	switch format {
	case Nil:
		return nil
	case True:
		return true
	case False:
		return false
	case PostiveFixIntMask:
		return uint64(t)
	case NegativeFixIntMask:
		return int64(t)
		// case Ext8, Ext16, Ext32:
	case Float32:
		var value float32
		_ = binary.Read(r, binary.BigEndian, &value)
		return float64(value)
	case Float64:
		var value float64
		_ = binary.Read(r, binary.BigEndian, &value)
		return value
	case UInt8:
		var value uint8
		_ = binary.Read(r, binary.BigEndian, &value)
		return uint64(value)
	case UInt16:
		var value uint16
		_ = binary.Read(r, binary.BigEndian, &value)
		return uint64(value)
	case UInt32:
		var value uint32
		_ = binary.Read(r, binary.BigEndian, &value)
		return uint64(value)
	case UInt64:
		var value uint64
		_ = binary.Read(r, binary.BigEndian, &value)
		return value
	case Int8:
		var value int8
		_ = binary.Read(r, binary.BigEndian, &value)
		return int64(value)
	case Int16:
		var value int16
		_ = binary.Read(r, binary.BigEndian, &value)
		return int64(value)
	case Int32:
		var value int32
		_ = binary.Read(r, binary.BigEndian, &value)
		return int64(value)
	case Int64:
		var value int64
		_ = binary.Read(r, binary.BigEndian, &value)
		return value
		// case FixExt1, FixExt2, FixExt4, FixExt8, FixExt16:
	case FixStrMask, Str8, Str16, Str32:
		b := make([]byte, length)
		_, _ = r.Read(b)
		return bytes.NewBuffer(b).String()
	case Bin8, Bin16, Bin32:
		b := make([]byte, 0, length)
		_, _ = r.Read(b)
		return b
	}
	return nil
}

func getType(r *bytes.Reader, t byte) (format Format, length uint64) {
	// nil
	if t == byte(Nil) {
		return Format(Nil), 0
	}
	// singal byte mix format and length
	switch true {
	case byte(t>>7) == byte(PostiveFixIntMask):
		format = PostiveFixIntMask
		return
	case byte(t>>5) == byte(NegativeFixIntMask):
		format = NegativeFixIntMask
		return
	case byte(t>>5) == byte(FixStrMask):
		format = FixStrMask
		length = uint64(t & byte(^(FixStrMask << 5)))
		return
	case byte(t>>4) == byte(FixArrayMask):
		format = FixArrayMask
		length = uint64(t & byte(^(FixArrayMask << 4)))
		return
	case byte(t>>4) == byte(FixMapMask):
		format = FixMapMask
		length = uint64(t & byte(^(FixMapMask << 4)))
		return
	}

	format = Format(t)
	// not exist type
	if format <= NeverUsed || format >= End {
		panic(fmt.Sprintf("Unknow format %x", format))
	}
	// split format and length
	switch format {
	case Nil, True, False:
	case Bin8, Ext8, Str8:
		var l uint8
		_ = binary.Read(r, binary.BigEndian, &l)
		length = uint64(l)
	case Bin16, Ext16, Str16, Array16, Map16:
		var l uint16
		_ = binary.Read(r, binary.BigEndian, &l)
		length = uint64(l)
	case Bin32, Ext32, Str32, Array32, Map32:
		var l uint32
		_ = binary.Read(r, binary.BigEndian, &l)
		length = uint64(l)
	}
	return
}
