package cipherbook

import "strings"

type Family int

const (
	FamilyUnknown Family = iota
	FamilyAEAD
	FamilyCBC
	FamilyStream
	FamilyBroken
)

type Fitness int

const (
	FitnessUnknown Fitness = iota
	Fit
	Unfit
	Refuse
)

type Entry struct {
	Name    string
	Family  Family
	Kernel  bool
	Fitness Fitness
}

const (
	baseIPv4      = 20 + 8 + 4
	ipv6Extra     = 20
	aeadOverhead  = baseIPv4 + 4 + 16
	cbcFixed      = baseIPv4 + 16 + 4 + 16
	streamFixed   = baseIPv4 + 16 + 4
	DefaultAuth   = "SHA1"
	unknownHMAC   = 64
	OverheadAEAD4 = aeadOverhead
)

var hmacBytes = map[string]int{
	"SHA1": 20, "SHA224": 28, "SHA256": 32, "SHA384": 48, "SHA512": 64,
	"SHA3-256": 32, "SHA3-384": 48, "SHA3-512": 64, "BLAKE2B512": 64, "BLAKE2S256": 32, "WHIRLPOOL": 64, "RMD160": 20,
}

var refusedAuth = map[string]bool{"MD5": true, "NONE": true, "MD4": true}

var refusedNames = map[string]bool{
	"NONE": true, "BF-CBC": true, "BF-CFB": true, "BF-OFB": true,
	"RC2-CBC": true, "RC2-40-CBC": true, "RC2-64-CBC": true, "RC2-CFB": true, "RC2-OFB": true,
	"CAST5-CBC": true, "CAST5-CFB": true, "CAST5-OFB": true,
	"DES-CBC": true, "DES-CFB": true, "DES-OFB": true, "DESX-CBC": true,
	"SEED-CBC": true, "SEED-CFB": true, "SEED-OFB": true, "IDEA-CBC": true, "IDEA-CFB": true, "IDEA-OFB": true,
	"RC4": true, "RC5-CBC": true,
}

var kernelCapable = map[string]bool{
	"AES-128-GCM": true, "AES-192-GCM": true, "AES-256-GCM": true, "CHACHA20-POLY1305": true,
}

func Canonical(name string) string { return strings.ToUpper(strings.TrimSpace(name)) }

func Lookup(name string) Entry {
	n := Canonical(name)
	e := Entry{Name: n}
	switch {
	case n == "":
		return e
	case refusedNames[n] || strings.HasPrefix(n, "DES-"):
		e.Family, e.Fitness = FamilyBroken, Refuse
	case n == "CHACHA20-POLY1305" || strings.HasSuffix(n, "-GCM"):
		e.Family = FamilyAEAD
		e.Kernel = kernelCapable[n]
		if e.Kernel {
			e.Fitness = Fit
		} else {
			e.Fitness = Unfit
		}
	case strings.HasSuffix(n, "-CBC"):
		e.Family, e.Fitness = FamilyCBC, Unfit
	case strings.HasSuffix(n, "-CFB") || strings.HasSuffix(n, "-CFB1") || strings.HasSuffix(n, "-CFB8") || strings.HasSuffix(n, "-OFB"):
		e.Family, e.Fitness = FamilyStream, Unfit
	}
	return e
}

type Verdict struct {
	Fitness Fitness
	Mixed   bool
	Refused []string
	Unknown []string
}

func SplitList(list string) []string {
	var out []string
	for _, n := range strings.Split(list, ":") {
		if n = Canonical(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func Classify(names []string, auth string) Verdict {
	v := Verdict{}
	if a := Canonical(auth); a != "" && refusedAuth[a] {
		v.Refused = append(v.Refused, "auth "+a)
	}
	if len(names) == 0 {
		if len(v.Refused) > 0 {
			v.Fitness = Refuse
			return v
		}
		v.Fitness = Fit
		return v
	}
	fit, unfit := 0, 0
	for _, n := range names {
		e := Lookup(n)
		switch e.Fitness {
		case Refuse:
			v.Refused = append(v.Refused, e.Name)
		case Fit:
			fit++
		case Unfit:
			unfit++
		default:
			v.Unknown = append(v.Unknown, e.Name)
			unfit++
		}
	}
	switch {
	case len(v.Refused) > 0:
		v.Fitness = Refuse
	case fit > 0 && unfit == 0:
		v.Fitness = Fit
	case fit == 0:
		v.Fitness = Unfit
	default:
		v.Fitness, v.Mixed = Fit, true
	}
	return v
}

func KernelCapable(names []string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if !Lookup(n).Kernel {
			return false
		}
	}
	return true
}

func UsesAES(names []string) bool {
	if len(names) == 0 {
		return true
	}
	for _, n := range names {
		if strings.HasPrefix(Canonical(n), "AES-") {
			return true
		}
	}
	return false
}

func Overhead(names []string, auth string, ipv6 bool) int {
	hmac, ok := hmacBytes[Canonical(auth)]
	if Canonical(auth) == "" {
		hmac, ok = hmacBytes[DefaultAuth], true
	}
	if !ok {
		hmac = unknownHMAC
	}
	worst := 0
	if len(names) == 0 {
		worst = aeadOverhead
	}
	for _, n := range names {
		var o int
		switch Lookup(n).Family {
		case FamilyAEAD:
			o = aeadOverhead
		case FamilyCBC:
			o = cbcFixed + hmac
		case FamilyStream:
			o = streamFixed + hmac
		default:
			o = cbcFixed + unknownHMAC
		}
		if o > worst {
			worst = o
		}
	}
	if ipv6 {
		worst += ipv6Extra
	}
	return worst
}
