package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"sync"
	"time"
)

func main() {
	// The file is in between "items/wshield.cel" and "levels/l1data/hero1.dun".
	// Since we know it is a DUN file, and since we know it uses the Cathedral
	// tileset, it is reasonable to assume that the DUN file is located in the
	// "levels\l1data\" subdirectory. Furthermore, the file name will start with a
	// character up until 'h', as it should come alphabetically before
	// "hero1.dun".
	const charsetFirstChar = "ABCDEFGH0123456789-_"
	n := runtime.NumCPU()
	fmt.Println("num CPU:", n)
	m := len(charsetFirstChar) / n
	wg := &sync.WaitGroup{}
	startTime := time.Now()
	for i := 0; i < n; i++ {
		start := i * m
		end := (i + 1) * m
		if end > len(charsetFirstChar) {
			end = len(charsetFirstChar)
		}
		part := charsetFirstChar[start:end]
		wg.Add(1)
		go brute(part, wg)
	}
	wg.Wait()
	timeTaken := time.Since(startTime)
	fmt.Println("timeTaken:", timeTaken)
}

func brute(charsetFirstChar string, wg *sync.WaitGroup) {
	const (
		charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	)
	first := true
	const n = 8
	fmt.Println("n:", n)
	const ext = ".DUN"
	dunName := make([]byte, n+len(ext))
	for i := 0; i < len(ext); i++ {
		j := len(dunName) - len(ext) + i
		dunName[j] = ext[i]
	}
	// Generate precomputed hash of prefix.
	prefix := []byte(`LEVELS\L1DATA\`)
	preA := hashPrefix(prefix, hashPathA)
	preB := hashPrefix(prefix, hashPathB)
	for _, a := range charsetFirstChar {
		dunName[0] = byte(a)
		for _, b := range charset {
			dunName[1] = byte(b)
			fmt.Printf("b: '%c%c'\n", a, b)
			for _, c := range charset {
				dunName[2] = byte(c)
				for _, d := range charset {
					dunName[3] = byte(d)
					for _, e := range charset {
						dunName[4] = byte(e)
						for _, f := range charset {
							dunName[5] = byte(f)
							for _, g := range charset {
								dunName[6] = byte(g)
								for _, h := range charset {
									dunName[7] = byte(h)
									if first {
										fmt.Println("dunName (first):", string(dunName))
										first = false
									}
									// copy precomputed hash; pass-by-value.
									if check(dunName, preA, preB) {
										fmt.Println("FOUND:", string(dunName))
										data := []byte(dunName)
										const outputPath = "found_hash.txt"
										fmt.Println("creating %q", outputPath)
										if err := ioutil.WriteFile(outputPath, data, 0644); err != nil {
											log.Printf("unable to create file %q", outputPath)
										}
										os.Exit(1)
									}
								}
							}
						}
					}
				}
			}
		}
	}
	wg.Done()
}

func check(relPath []byte, preA, preB prehash) bool {
	// hash A 0xB29FC135 and hash B 0x22575C4A
	const (
		wantHashA = 0xB29FC135
		wantHashB = 0x22575C4A
	)
	hashA := preA.genHash(relPath, hashPathA)
	//fmt.Printf("A: 0x%08X\n", hashA)
	//fmt.Printf("B: 0x%08X\n", hashB)
	foundA := hashA == wantHashA
	if foundA {
		fmt.Println("relPath (found A):", string(relPath))
		hashB := preB.genHash(relPath, hashPathB)
		foundB := hashB == wantHashB
		if foundB {
			fmt.Println("relPath (found A and B):", string(relPath))
			return true
		}
	}
	return false
}

// --- [ decrypt ] -------------------------------------------------------------

var (
	// Lookup table used during decryption.
	cryptTable [0x500]uint32
)

func init() {
	// Initialize crypt table.
	initCryptTable()
}

// initCryptTable initializes the lookup table used during decryption.
func initCryptTable() {
	//start := time.Now()
	seed := uint32(0x00100001)
	for index1 := 0; index1 < 0x100; index1++ {
		index2 := index1
		for i := 0; i < 5; i++ {
			seed = (seed*125 + 3) % 0x2AAAAB
			temp1 := (seed & 0xFFFF) << 0x10
			seed = (seed*125 + 3) % 0x2AAAAB
			temp2 := (seed & 0xFFFF)
			cryptTable[index2] = (temp1 | temp2)
			index2 += 0x100
		}
	}
	// Takes on average 60.00 µs.
	//dbg.Println("init of crypt tables took:", time.Since(start))
}

// hashType represents the set of hash types.
type hashType uint32

// Hash types.
const (
	// Hash of relative file path, which specifies an index hash the hash table,
	// from where to start searching for the hash entry associated with the given
	// file.
	hashTableIndex hashType = 0x000
	// Hash of relative file path, using method A.
	hashPathA hashType = 0x100
	// Hash of relative file path, using method B.
	hashPathB hashType = 0x200
	// Hash of the file name, which specifies the encryption key of the file.
	hashFileKey hashType = 0x300
)

// precomputed hash for prefix of a string.
type prehash struct {
	seed1 uint32
	seed2 uint32
}

// hashPrefix returns a precomputed hash based on the given prefix.
func hashPrefix(prefix []byte, hashType hashType) prehash {
	seed1 := uint32(0x7FED7FED)
	seed2 := uint32(0xEEEEEEEE)
	for i := 0; i < len(prefix); i++ {
		v := uint32(prefix[i])
		seed1 = cryptTable[uint32(hashType)+v] ^ (seed1 + seed2)
		seed2 = v + seed1 + seed2 + (seed2 << 5) + 3
	}
	return prehash{
		seed1: seed1,
		seed2: seed2,
	}
}

// genHash returns the hash of the given string, based on the specified hash
// type and the precomputed hash of the string prefix.
func (pre prehash) genHash(s []byte, hashType hashType) uint32 {
	seed1 := pre.seed1
	seed2 := pre.seed2
	for i := 0; i < len(s); i++ {
		v := uint32(s[i])
		seed1 = cryptTable[uint32(hashType)+v] ^ (seed1 + seed2)
		seed2 = v + seed1 + seed2 + (seed2 << 5) + 3
	}
	return seed1
}

// genHash returns the hash of the given string, based on the specified hash
// type.
func genHash(s []byte, hashType hashType) uint32 {
	seed1 := uint32(0x7FED7FED)
	seed2 := uint32(0xEEEEEEEE)
	for i := 0; i < len(s); i++ {
		v := uint32(s[i])
		seed1 = cryptTable[uint32(hashType)+v] ^ (seed1 + seed2)
		seed2 = v + seed1 + seed2 + (seed2 << 5) + 3
	}
	return seed1
}

// hashAB contains both the A and B hashes of a given file, to be used as key
// for file listings.
type hashAB struct {
	// Hash of relative file path; using method A.
	hashA uint32
	// Hash of relative file path; using method B.
	hashB uint32
}
