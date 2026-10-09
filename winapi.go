package main

import (
	"syscall"
	"unsafe"
)

var (
	k32   = syscall.NewLazyDLL("kernel32.dll")
	nt    = syscall.NewLazyDLL("ntdll.dll")
	adv   = syscall.NewLazyDLL("advapi32.dll")
	shell = syscall.NewLazyDLL("shell32.dll")

	pOpenProcess              = k32.NewProc("OpenProcess")
	pCloseHandle              = k32.NewProc("CloseHandle")
	pGetCurrentProcess        = k32.NewProc("GetCurrentProcess")
	pDuplicateHandle          = k32.NewProc("DuplicateHandle")
	pCreateMutexW             = k32.NewProc("CreateMutexW")
	pQueryFullProcessImage    = k32.NewProc("QueryFullProcessImageNameW")
	pCreateToolhelp32Snapshot = k32.NewProc("CreateToolhelp32Snapshot")
	pProcess32FirstW          = k32.NewProc("Process32FirstW")
	pProcess32NextW           = k32.NewProc("Process32NextW")
	pReadProcessMemory        = k32.NewProc("ReadProcessMemory")
	pGetLastError             = k32.NewProc("GetLastError")

	pNtQuerySystemInformation = nt.NewProc("NtQuerySystemInformation")
	pNtQueryObject            = nt.NewProc("NtQueryObject")
	pNtQueryInformationProcess = nt.NewProc("NtQueryInformationProcess")

	pOpenProcessToken      = adv.NewProc("OpenProcessToken")
	pLookupPrivilegeValueW = adv.NewProc("LookupPrivilegeValueW")
	pAdjustTokenPrivileges = adv.NewProc("AdjustTokenPrivileges")
	pGetTokenInformation   = adv.NewProc("GetTokenInformation")
)

const (
	processDupHandle                 = 0x0040
	processVMRead                    = 0x0010
	processQueryLimitedInformation   = 0x1000
	th32csSnapProcess                = 0x00000002
	tokenQuery                       = 0x0008
	tokenAdjustPrivileges            = 0x0020
	sePrivilegeEnabled               = 0x00000002
	tokenElevation                   = 20
	errorAlreadyExists               = 183
	stillActive                      = 259
)

type processEntry32 struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type luid struct {
	LowPart  uint32
	HighPart int32
}

type tokenPrivileges struct {
	PrivilegeCount uint32
	LowPart        uint32
	HighPart       int32
	Attributes     uint32
}

func lastErr() error {
	code, _, _ := pGetLastError.Call()
	if code == 0 {
		return nil
	}
	return syscall.Errno(code)
}

func openProcess(access, pid uint32) (syscall.Handle, error) {
	h, _, err := pOpenProcess.Call(uintptr(access), 0, uintptr(pid))
	if h == 0 {
		if err == nil || err == syscall.Errno(0) {
			err = lastErr()
		}
		return 0, err
	}
	return syscall.Handle(h), nil
}

func closeHandle(h syscall.Handle) {
	if h != 0 {
		_, _, _ = pCloseHandle.Call(uintptr(h))
	}
}

func currentProcess() syscall.Handle {
	h, _, _ := pGetCurrentProcess.Call()
	return syscall.Handle(h)
}

func duplicateHandle(srcProc syscall.Handle, src uintptr, access, options uint32) (syscall.Handle, error) {
	var out uintptr
	r, _, err := pDuplicateHandle.Call(
		uintptr(srcProc),
		src,
		uintptr(currentProcess()),
		uintptr(unsafe.Pointer(&out)),
		uintptr(access), 0,
		uintptr(options),
	)
	if r == 0 {
		if err == nil || err == syscall.Errno(0) {
			err = lastErr()
		}
		return 0, err
	}
	return syscall.Handle(out), nil
}

func createNamed(name string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	h, _, callErr := pCreateMutexW.Call(0, 0, uintptr(unsafe.Pointer(p)))
	if h == 0 {
		if callErr == nil || callErr == syscall.Errno(0) {
			callErr = lastErr()
		}
		return 0, callErr
	}
	return syscall.Handle(h), nil
}

func alreadyExists() bool {
	code, _, _ := pGetLastError.Call()
	return code == errorAlreadyExists
}

func queryImageName(pid uint32) string {
	h, err := openProcess(processQueryLimitedInformation, pid)
	if err != nil {
		return ""
	}
	defer closeHandle(h)
	buf := make([]uint16, 32768)
	size := uint32(len(buf))
	r, _, _ := pQueryFullProcessImage.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
	if r == 0 || size == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size])
}

func snapshotProcesses() []processEntry32 {
	snap, _, _ := pCreateToolhelp32Snapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return nil
	}
	defer closeHandle(syscall.Handle(snap))

	var entry processEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	r, _, _ := pProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	var out []processEntry32
	for r != 0 {
		out = append(out, entry)
		entry = processEntry32{Size: entry.Size}
		r, _, _ = pProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return out
}

func ntStatus(r uintptr) error {
	if r == 0 {
		return nil
	}
	return syscall.Errno(r)
}

func ntQuerySystem(class uint32, buf []byte) (uint32, error) {
	var need uint32
	r, _, _ := pNtQuerySystemInformation.Call(
		uintptr(class),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&need)),
	)
	return need, ntStatus(r)
}

func ntQueryObject(handle syscall.Handle, class uint32, buf []byte) (uint32, error) {
	var need uint32
	r, _, _ := pNtQueryObject.Call(
		uintptr(handle),
		uintptr(class),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&need)),
	)
	return need, ntStatus(r)
}

func ntQueryProcess(handle syscall.Handle, class uint32, buf []byte) (uint32, error) {
	var need uint32
	r, _, _ := pNtQueryInformationProcess.Call(
		uintptr(handle),
		uintptr(class),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&need)),
	)
	return need, ntStatus(r)
}

func readProcessMemory(proc syscall.Handle, addr uintptr, n int) ([]byte, error) {
	buf := make([]byte, n)
	var got uintptr
	r, _, err := pReadProcessMemory.Call(
		uintptr(proc),
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(n),
		uintptr(unsafe.Pointer(&got)),
	)
	if r == 0 {
		if err == nil || err == syscall.Errno(0) {
			err = lastErr()
		}
		return nil, err
	}
	return buf[:got], nil
}

func initCOM() {
	// The file dialog needs the UI thread in an STA. Without this, the
	// elevated process can open a window that never accepts input.
	syscall.NewLazyDLL("ole32.dll").NewProc("CoInitializeEx").Call(0, 2)
}

func enableDebugPrivilege() {
	var token syscall.Handle
	r, _, _ := pOpenProcessToken.Call(uintptr(currentProcess()), tokenAdjustPrivileges|tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return
	}
	defer closeHandle(token)

	var id luid
	name, _ := syscall.UTF16PtrFromString("SeDebugPrivilege")
	r, _, _ = pLookupPrivilegeValueW.Call(0, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&id)))
	if r == 0 {
		return
	}
	tp := tokenPrivileges{
		PrivilegeCount: 1,
		LowPart:        id.LowPart,
		HighPart:       id.HighPart,
		Attributes:     sePrivilegeEnabled,
	}
	_, _, _ = pAdjustTokenPrivileges.Call(uintptr(token), 0, uintptr(unsafe.Pointer(&tp)), 0, 0, 0)
}

func isAdmin() bool {
	var token syscall.Handle
	r, _, _ := pOpenProcessToken.Call(uintptr(currentProcess()), tokenQuery, uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer closeHandle(token)
	var elev uint32
	var out uint32
	r, _, _ = pGetTokenInformation.Call(
		uintptr(token),
		tokenElevation,
		uintptr(unsafe.Pointer(&elev)),
		4,
		uintptr(unsafe.Pointer(&out)),
	)
	return r != 0 && elev != 0
}
