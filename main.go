package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) > 1 {
		enableDebugPrivilege()
		switch os.Args[1] {
		case "-probe":
			os.Exit(runProbe())
		case "-selftest":
			os.Exit(runSelfTest())
		case "-open":
			path := filepath.Join(os.TempDir(), "weixintwin-open.txt")
			if len(os.Args) > 2 {
				path = os.Args[2]
			}
			f, err := os.Create(path)
			if err != nil {
				os.Exit(2)
			}
			os.Stdout = f
			code := runOpen()
			f.Close()
			os.Exit(code)
		case "-types":
			path := filepath.Join(os.TempDir(), "weixintwin-types.txt")
			if len(os.Args) > 2 {
				path = os.Args[2]
			}
			f, err := os.Create(path)
			if err != nil {
				os.Exit(2)
			}
			os.Stdout = f
			code := runTypes()
			f.Close()
			os.Exit(code)
		case "-why":
			path := filepath.Join(os.TempDir(), "weixintwin-why.txt")
			if len(os.Args) > 2 {
				path = os.Args[2]
			}
			f, err := os.Create(path)
			if err != nil {
				os.Exit(2)
			}
			os.Stdout = f
			os.Stderr = f
			code := runWhy()
			f.Close()
			os.Exit(code)
		}
	}
	runUI()
}

func runProbe() int {
	exe := discoverExe()
	fmt.Println("exe:", exe)
	fmt.Println("version:", wechatVersion(exe))
	fmt.Println("admin:", isAdmin())
	info, err := detectTable()
	if err != nil {
		fmt.Println("detect:", err)
		return 1
	}
	fmt.Printf("handle table: mode=%d mutantType=%d\n", info.mode, info.typeIndex)
	procs := listWeChat()
	if len(procs) == 0 {
		fmt.Println("wechat: not running")
		return 0
	}
	for _, p := range procs {
		kind := "child"
		if p.Main {
			kind = "main"
		}
		fmt.Printf("pid %d %s %s\n", p.PID, kind, p.Exe)
	}
	names, err := describeMutexes(wechatPIDs())
	if err != nil {
		fmt.Println("describe:", err)
		return 1
	}
	fmt.Println("mutexes:")
	for _, name := range names {
		mark := ""
		if isSingletonMutex(name) {
			mark = "  <-- singleton"
		}
		fmt.Println(" ", name, mark)
	}
	return 0
}

func runTypes() int {
	fmt.Println("admin:", isAdmin())
	name := `Local\WeixinTwin_TypeProbe_Types`
	probe, err := createNamed(name)
	fmt.Println("probe:", err)
	if err != nil {
		return 1
	}
	defer closeHandle(probe)
	want := uintptr(probe)
	myPID := uint32(os.Getpid())
	if raw, err := querySystem(systemExtendedHandleInformation); err == nil {
		for _, h := range parseExtended(raw) {
			if h.PID == myPID && h.Handle == want {
				fmt.Printf("extended: type=%d handle=%d\n", h.ObjectType, h.Handle)
			}
		}
		counts := map[uint16]int{}
		for _, h := range parseExtended(raw) {
			counts[h.ObjectType]++
		}
		fmt.Println("extended type histogram:")
		for t, n := range counts {
			fmt.Printf("  type %d = %d\n", t, n)
		}
	} else {
		fmt.Println("extended:", err)
	}
	if raw, err := querySystem(systemHandleInformation); err == nil {
		for _, h := range parseLegacy(raw) {
			if h.PID == myPID && h.Handle == (want&0xFFFF) {
				fmt.Printf("legacy: type=%d handle=%d\n", h.ObjectType, h.Handle)
			}
		}
	} else {
		fmt.Println("legacy:", err)
	}
	return 0
}

func runWhy() int {
	fmt.Println("admin:", isAdmin())
	info, err := detectTable()
	fmt.Printf("table mode=%d type=%d err=%v\n", info.mode, info.typeIndex, err)
	procs := listWeChat()
	fmt.Println("processes:", len(procs))
	for _, p := range procs {
		fmt.Printf("  pid %d parent %d main=%v %s\n", p.PID, p.Parent, p.Main, p.Exe)
	}
	if err != nil {
		return 1
	}
	set := map[uint32]bool{}
	for _, p := range procs {
		set[p.PID] = true
	}
	entries, err := handlesFor(info, set)
	fmt.Println("handles:", len(entries), "err:", err)
	openFail, dupFail, nameFail, empty, matched := 0, 0, 0, 0, 0
	dupErrs := map[string]int{}
	for _, entry := range entries {
		proc, e := openProcess(processDupHandle, entry.PID)
		if e != nil {
			openFail++
			continue
		}
		dup, e := duplicateHandle(proc, entry.Handle, queryNameAccess, 0)
		if e != nil || dup == 0 {
			dupFail++
			if e != nil {
				dupErrs[e.Error()]++
			}
			closeHandle(proc)
			continue
		}
		objName, nameErr := objectName(dup)
		closeHandle(dup)
		closeHandle(proc)
		if nameErr != nil {
			nameFail++
			continue
		}
		if objName == "" {
			empty++
			continue
		}
		low := strings.ToLower(objName)
		if strings.Contains(low, "wechat") || strings.Contains(low, "weixin") || strings.Contains(low, "instance") || strings.Contains(low, "xweb") {
			fmt.Printf("  name pid=%d type=%d %s\n", entry.PID, entry.ObjectType, objName)
		}
		if isSingletonMutex(objName) {
			matched++
		}
	}
	fmt.Printf("openFail=%d dupFail=%d nameFail=%d empty=%d matched=%d\n", openFail, dupFail, nameFail, empty, matched)
	for msg, n := range dupErrs {
		fmt.Printf("  dup err %d: %s\n", n, msg)
	}
	return 0
}

func runSelfTest() int {
	name := `Local\XWeChat_XWEB_Instance_Identity_Mutex_Name_WeixinTwinSelfTest`
	first, err := createNamed(name)
	if err != nil {
		fmt.Println("create:", err)
		return 1
	}
	defer closeHandle(first)

	n, names, err := closeSingletonMutexes([]uint32{uint32(os.Getpid())})
	fmt.Println("closed", n, err)
	for _, item := range names {
		fmt.Println(" ", item)
	}
	if err != nil || n < 1 || !strings.Contains(strings.Join(names, "\n"), "XWeChat_XWEB_Instance_Identity_Mutex_Name") {
		fmt.Println("FAIL: did not close the probe mutex")
		return 1
	}

	second, err := createNamed(name)
	if err != nil {
		fmt.Println("recreate:", err)
		return 1
	}
	defer closeHandle(second)
	if alreadyExists() {
		fmt.Println("FAIL: mutex still exists after close")
		return 1
	}
	fmt.Println("PASS")
	return 0
}

func runOpen() int {
	exe := discoverExe()
	err := OpenAnother(exe, 1, func(line string) {
		fmt.Println(line)
	})
	if err != nil {
		fmt.Println("ERROR:", err)
		return 1
	}
	fmt.Println("OK")
	return 0
}
