package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"time"
	"unicode"

	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
)

/*
Aim : generate a EIP-55 complient ethereum address from a randomly-generated private key.
Step 1 : Genrate a 256 bit - 32 bytes private key.
Step 2 : Encode it to hexadecimal format.
Step 3 : Get (X,Y) on secp256k1 elliptic curve ( Elliptic Curve Cryptography ).
Generator Point:
(55066263022277343669578718895168534326250603453777594175500187360389116729240,
32670510020758816978083085130507043184471273380659243275938904335757337482424)
= (0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
Step 4 : Concatenate (X,Y)
Stpe 5 : Get hash by using Keccak256 ( legacy )
Step 6 : address = last 20 bytes of hash bytes slice.
*/

func main() {
	// privateKey := generatePrivateKey()
	// publicKey := generatePublicKeyFromPrivateKey(privateKey)
	// address := generateAddressFromPublicKey(publicKey)
	// address55 := encodeEIP55(address)
	// fmt.Printf("Is address valid: %t\n", isValidAddress(address55))
	prefix := "abcd"
	generateWithPrefix(prefix)
}

func isValidAddress(address string) bool {
	d := sha3.NewLegacyKeccak256()
	d.Write([]byte(strings.ToLower(address)))
	addressHashString := hex.EncodeToString(d.Sum(nil))
	addressHashRune := []rune(addressHashString)
	for i, val := range address {
		var valueHash int
		if unicode.IsLetter(addressHashRune[i]) {
			valueHash = int(addressHashRune[i]) - 87
		} else {
			valueHash = int(addressHashRune[i]) - 48
		}
		if unicode.IsLetter(val) {
			if unicode.IsUpper(val) {
				if valueHash >= 8 {
					continue
				} else {
					fmt.Printf("Big Address: %s Hash: %s \n", string(val), string(valueHash))
					return false
				}
			} else {
				if valueHash < 8 {
					continue
				} else {
					fmt.Printf("Small Address: %s Hash: %s \n", string(val), string(valueHash))
					return false
				}
			}
		} else {
			continue
		}
	}
	return true
}

func generatePrivateKey() []byte {
	newSource := rand.NewSource(time.Now().UnixNano())
	newRand := rand.New(newSource)
	privateKey := make([]byte, 32)
	_, err := newRand.Read(privateKey)
	if err != nil {
		return nil
	}
	privateKeyHex := make([]byte, hex.EncodedLen(len(privateKey)))
	hex.Encode(privateKeyHex, privateKey)
	// fmt.Printf("Private Key generated: %s \n\n", privateKeyHex)
	return privateKey
}

func generatePublicKeyFromPrivateKey(privateKey []byte) string {
	bitCurve := secp256k1.S256()
	x, y := bitCurve.ScalarBaseMult(privateKey)

	hexX := fmt.Sprintf("%x", x)
	hexY := fmt.Sprintf("%x", y)
	publicKey := hexX + hexY
	// fmt.Printf("X: %s\n", hexX)
	// fmt.Printf("Y: %s\n", hexY)
	// fmt.Printf("Public Key: %s\n\n", publicKey)
	return publicKey
}

func generateAddressFromPublicKey(publicKey string) string {
	d := sha3.NewLegacyKeccak256()
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return ""
	}
	d.Write(publicKeyBytes)
	hash := d.Sum(nil)
	address := hex.EncodeToString(hash[len(hash)-20:])
	// fmt.Printf("Public Address: %s \n", address)
	return address
}

func encodeEIP55(address string) string {
	d := sha3.NewLegacyKeccak256()
	d.Write([]byte(address))
	addressHash := d.Sum(nil)
	addressHashString := hex.EncodeToString(addressHash)
	fmt.Printf("Keccak256 Hash of address:  %s\n", addressHashString)
	addressHashRune := []rune(addressHashString)
	addressRune := []rune(address)
	addressRune55 := []rune{}
	for i, val := range addressRune {
		value := 0
		if unicode.IsLetter(addressHashRune[i]) {
			value = int(addressHashRune[i]) - 87
		} else {
			value = int(addressHashRune[i]) - 48
		}
		if value >= 8 {
			addressRune55 = append(addressRune55, []rune(strings.ToUpper(string(val)))[0])
		} else {
			addressRune55 = append(addressRune55, val)
		}
	}
	fmt.Printf("EIP-55 encoded address:%s\n", string(addressRune55))
	return string(addressRune55)
}

func generateWithPrefix(prefix string) {
	/*
		Math behind it :
		Probability of a given character occuring at any place = 1/16
		Hence probability that a given prefix of length 'n' will occur is (1/16)^n.
		(being no contraint on number of occurences & other places)
		Thus, mathematically speaking, longer the prefix, longer will* be the waiting time.

		*Note: In the end this is just some probability, you might get the required prefix in
				first attempt or maybe an eternity later :)
	*/

	startTime := time.Now()
	length := len(prefix)
	h, m, s := startTime.Clock()
	fmt.Printf("Prefix: %s\nStart time: %d:%d:%d\n", prefix, h, m, s)
	for {
		privateKey := generatePrivateKey()
		if privateKey != nil {
			publicKey := generatePublicKeyFromPrivateKey(privateKey)
			if publicKey != "" {
				address := generateAddressFromPublicKey(publicKey)
				if address != "" {
					if address[:length] == prefix {
						privateKeyHex := make([]byte, hex.EncodedLen(len(privateKey)))
						hex.Encode(privateKeyHex, privateKey)
						fmt.Printf("EUREKA! EUREKA! \nPrivate key: %s \nPublic key: %s \nAddress: %s \n", privateKeyHex, publicKey, address)
						break
					}
				}
			}
		}
	}
	finishTime := time.Now()
	h, m, s = finishTime.Clock()
	fmt.Printf("Finish time: %d:%d:%d \n", h, m, s)
	timeTaken := finishTime.Sub(startTime)
	fmt.Printf("Time elapsed : %s\n", timeTaken.String())
}
