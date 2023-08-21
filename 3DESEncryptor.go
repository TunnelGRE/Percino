/*
            Project Augustus Loader
                VERSION: 1.0
 AUTHOR: @tunnelgre - https://twitter.com/tunnelgre
	              

*/


package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {
	key := generateRandomBytes(24) 
	iv := generateRandomBytes(des.BlockSize) 

	fmt.Printf("Key: %s\n", formatShellcode(key))  
	fmt.Printf("IV: %s\n", formatShellcode(iv))   

	shellcode := []byte("")

	// Encryption
	encryptedShellcode, err := encryptDES3(shellcode, key, iv)
	if err != nil {
		fmt.Println("Error 3DES:", err)
		return
	}

	fmt.Printf("Shellcode encrypted: %s\n", formatShellcode(encryptedShellcode))


}

func generateRandomBytes(size int) []byte {
	randomBytes := make([]byte, size)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate random bytes: %v", err))
	}
	return randomBytes
}

func encryptDES3(plaintext, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext = pad(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(plaintext))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return ciphertext, nil
}



func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}


func shellcodeToHex(data []byte) string {
	return hex.EncodeToString(data)
}

func formatShellcode(data []byte) string {
	output := ""
	for _, b := range data {
		output += fmt.Sprintf("\\x%02x", b)
	}
	return output
}
