package main

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	key := generateRandomBytes(24) 
	iv := generateRandomBytes(des.BlockSize) 

	fmt.Printf("Key: %s\n", formatShellcode(key))  
	fmt.Printf("IV: %s\n", formatShellcode(iv))   

	shellcode := []byte(" ")

	// Stampa la shellcode iniziale
	fmt.Printf("Original shellcode: %s\n", shellcodeToHex(shellcode))

	// Encryption
	encryptedShellcode, err := encryptDES3(shellcode, key, iv)
	if err != nil {
		fmt.Println("Error 3DES:", err)
		return
	}

	fmt.Printf("Shellcode encrypted: %s\n", formatShellcode(encryptedShellcode))

	decryptedShellcode, err := decryptDES3(encryptedShellcode, key, iv)
	if err != nil {
		fmt.Println("Errore nella decifratura del 3DES:", err)
		return
	}

	fmt.Printf("Shellcode decifrato: %s\n", shellcodeToHex(decryptedShellcode))
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

func decryptDES3(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("Il testo cifrato non ha una lunghezza valida")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	// Rimuovi il padding dal testo decifrato
	decrypted = unpad(decrypted)

	return decrypted, nil
}

func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
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
