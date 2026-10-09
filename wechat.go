package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	// WeChat 4.x (Weixin.exe) and 3.x (WeChat.exe) use different names.
	// XWEB is the Chromium-shell singleton in 4.1; the older name is kept
	// so a 3.x install still works. Update/plugin mutexes are left alone.
	mutexMarks = "XWeChat_XWEB_Instance_Identity_Mutex_Name,_WeChat_App_Instance_Identity_Mutex_Name,XWeChat_App_Instance_Identity_Mutex_Name"

	systemExtendedHandleInformation = 64
	systemHandleInformation         = 16
	objectNameInformation           = 1
	processCommandLineInformation   = 60

	statusInfoLengthMismatch = syscall.Errno(0xC0000004)
	statusBufferOverflow     = syscall.Errno(0x80000005)

	duplicateCloseSource = 0x1
	duplicateSameAccess  = 0x2

	// DUPLICATE_SAME_ACCESS fails with "request is not supported" on some of
	// WeChat's handles once we are elevated. Asking only for the right to
	// query the object name succeeds, and that is all the lookup needs.
	queryNameAccess = 0x0001
)

type handleMode int

const (
	modeUnknown handleMode = iota
	modeExtended
	modeLegacy
)

type handleEntry struct {
	PID        uint32
	Handle     uintptr
	ObjectType uint16
}

var (
	errNeedAdmin = errors.New("微信正在运行，但没能解开它的单实例限制。请点「以管理员身份运行」后再试。")
	errNoWindow  = errors.New("没有出现新的微信窗口。等两秒再试；仍不行就用管理员身份运行。")
	errNoWeChat  = errors.New("没有找到微信。请先安装，或手动选择 Weixin.exe。")
)

func isLengthMismatch(err error) bool {
	return errors.Is(err, statusInfoLengthMismatch) || errors.Is(err, statusBufferOverflow)
}

func configPath() string {
	base := os.Getenv("APPDATA")
	if base == "" {
		base = "."
	}
	return filepath.Join(base, "WeixinTwin", "config.json")
}

func loadSavedExe() string {
	body, err := os.ReadFile(configPath())
	if err != nil {
		return ""
	}
	var cfg struct {
		Exe string `json:"exe"`
	}
	if json.Unmarshal(body, &cfg) != nil || !fileExists(cfg.Exe) {
		return ""
	}
	return cfg.Exe
}

func saveExe(path string) {
	_ = os.MkdirAll(filepath.Dir(configPath()), 0o755)
	body, _ := json.MarshalIndent(map[string]string{"exe": path}, "", "  ")
	_ = os.WriteFile(configPath(), body, 0o644)
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func discoverExe() string {
	if saved := loadSavedExe(); saved != "" {
		return saved
	}
	for _, p := range listWeChat() {
		if p.Main && fileExists(p.Exe) {
			return p.Exe
		}
	}
	if p := installFromRegistry(); p != "" {
		return p
	}
	for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)")} {
		if base == "" {
			continue
		}
		for _, rel := range []string{`Tencent\Weixin\Weixin.exe`, `Tencent\WeChat\WeChat.exe`} {
			candidate := filepath.Join(base, rel)
			if fileExists(candidate) {
				return candidate
			}
		}
	}
	return ""
}

func installFromRegistry() string {
	k, err := syscall.UTF16PtrFromString(`Software\Tencent\Weixin`)
	if err != nil {
		return ""
	}
	var key syscall.Handle
	r, _, _ := syscall.NewLazyDLL("advapi32.dll").NewProc("RegOpenKeyExW").Call(
		uintptr(0x80000001), // HKCU
		uintptr(unsafe.Pointer(k)),
		0,
		0x20019, // KEY_READ
		uintptr(unsafe.Pointer(&key)),
	)
	if r == 0 {
		defer syscall.NewLazyDLL("advapi32.dll").NewProc("RegCloseKey").Call(uintptr(key))
		if dir := regString(key, "InstallPath"); dir != "" {
			candidate := filepath.Join(strings.Trim(dir, `"`), "Weixin.exe")
			if fileExists(candidate) {
				return candidate
			}
		}
	}
	for _, path := range []string{
		`SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WeChat`,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WeChat`,
	} {
		name, err := syscall.UTF16PtrFromString(path)
		if err != nil {
			continue
		}
		var key syscall.Handle
		r, _, _ := syscall.NewLazyDLL("advapi32.dll").NewProc("RegOpenKeyExW").Call(
			uintptr(0x80000002), // HKLM
			uintptr(unsafe.Pointer(name)),
			0,
			0x20019|0x0200, // KEY_READ | KEY_WOW64_32KEY
			uintptr(unsafe.Pointer(&key)),
		)
		if r != 0 {
			continue
		}
		dir := regString(key, "InstallLocation")
		syscall.NewLazyDLL("advapi32.dll").NewProc("RegCloseKey").Call(uintptr(key))
		for _, exe := range []string{"Weixin.exe", "WeChat.exe"} {
			candidate := filepath.Join(strings.Trim(dir, `"`), exe)
			if fileExists(candidate) {
				return candidate
			}
		}
	}
	return ""
}

func regString(key syscall.Handle, name string) string {
	n, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	buf := make([]uint16, 1024)
	size := uint32(len(buf) * 2)
	var kind uint32
	r, _, _ := syscall.NewLazyDLL("advapi32.dll").NewProc("RegQueryValueExW").Call(
		uintptr(key),
		uintptr(unsafe.Pointer(n)),
		0,
		uintptr(unsafe.Pointer(&kind)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
	)
	if r != 0 || kind != 1 || size < 2 {
		return ""
	}
	return syscall.UTF16ToString(buf[:size/2])
}

func wechatVersion(exe string) string {
	if exe == "" {
		return "未找到"
	}
	entries, err := os.ReadDir(filepath.Dir(exe))
	if err != nil {
		return "已安装"
	}
	best := ""
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == "" || entry.Name()[0] < '0' || entry.Name()[0] > '9' {
			continue
		}
		dll := filepath.Join(filepath.Dir(exe), entry.Name(), "Weixin.dll")
		old := filepath.Join(filepath.Dir(exe), entry.Name(), "WeChatWin.dll")
		if fileExists(dll) || fileExists(old) {
			if entry.Name() > best {
				best = entry.Name()
			}
		}
	}
	if best == "" {
		return "已安装"
	}
	return best
}

type weProcess struct {
	PID    uint32
	Parent uint32
	Exe    string
	Cmd    string
	Main   bool
}

func listWeChat() []weProcess {
	// Only the snapshot and the image path. Reading another process's
	// command line can stall the UI thread once this program is elevated.
	var raw []weProcess
	ids := map[uint32]bool{}
	for _, entry := range snapshotProcesses() {
		name := strings.ToLower(syscall.UTF16ToString(entry.ExeFile[:]))
		if name != "weixin.exe" && name != "wechat.exe" {
			continue
		}
		p := weProcess{
			PID:    entry.ProcessID,
			Parent: entry.ParentProcessID,
			Exe:    queryImageName(entry.ProcessID),
		}
		raw = append(raw, p)
		ids[p.PID] = true
	}
	for i := range raw {
		raw[i].Main = !ids[raw[i].Parent]
	}
	return raw
}

func mainProcesses() []weProcess {
	var mains []weProcess
	for _, p := range listWeChat() {
		if p.Main {
			mains = append(mains, p)
		}
	}
	return mains
}

func processCommandLine(pid uint32) string {
	h, err := openProcess(processQueryLimitedInformation|processVMRead, pid)
	if err != nil {
		return ""
	}
	defer closeHandle(h)
	buf := make([]byte, 8192)
	_, err = ntQueryProcess(h, processCommandLineInformation, buf)
	if isLengthMismatch(err) {
		return ""
	}
	if err != nil || len(buf) < 16 {
		return ""
	}
	length := binary.LittleEndian.Uint16(buf[0:2])
	ptr := uintptr(binary.LittleEndian.Uint64(buf[8:16]))
	if length < 2 || ptr == 0 {
		return ""
	}
	base := uintptr(unsafe.Pointer(&buf[0]))
	var raw []byte
	if ptr >= base && ptr+uintptr(length) <= base+uintptr(len(buf)) {
		start := int(ptr - base)
		raw = buf[start : start+int(length)]
	} else {
		copied, err := readProcessMemory(h, ptr, int(length))
		if err != nil {
			return ""
		}
		raw = copied
	}
	chars := make([]uint16, len(raw)/2)
	for i := range chars {
		chars[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
	}
	return syscall.UTF16ToString(chars)
}

func querySystem(class uint32) ([]byte, error) {
	size := 1 << 20
	for size < 512<<20 {
		buf := make([]byte, size)
		need, err := ntQuerySystem(class, buf)
		if err == nil {
			return buf, nil
		}
		if !isLengthMismatch(err) {
			return nil, err
		}
		if int(need) > size {
			size = int(need) + 1<<16
		} else {
			size *= 2
		}
	}
	return nil, errors.New("系统句柄表太大，读不完")
}

func parseExtended(raw []byte) []handleEntry {
	if len(raw) < 16 {
		return nil
	}
	count := binary.LittleEndian.Uint64(raw[0:8])
	const entrySize = 40
	out := make([]handleEntry, 0, 64)
	for i := uint64(0); i < count; i++ {
		off := 16 + int(i)*entrySize
		if off+entrySize > len(raw) {
			break
		}
		pid := binary.LittleEndian.Uint64(raw[off+8 : off+16])
		handle := binary.LittleEndian.Uint64(raw[off+16 : off+24])
		objType := binary.LittleEndian.Uint16(raw[off+28 : off+30])
		out = append(out, handleEntry{PID: uint32(pid), Handle: uintptr(handle), ObjectType: objType})
	}
	return out
}

func parseLegacy(raw []byte) []handleEntry {
	if len(raw) < 8 {
		return nil
	}
	count := binary.LittleEndian.Uint64(raw[0:8])
	const entrySize = 24
	out := make([]handleEntry, 0, 64)
	for i := uint64(0); i < count; i++ {
		off := 8 + int(i)*entrySize
		if off+20 > len(raw) {
			break
		}
		pid := binary.LittleEndian.Uint16(raw[off : off+2])
		objType := raw[off+4]
		handle := binary.LittleEndian.Uint16(raw[off+6 : off+8])
		out = append(out, handleEntry{PID: uint32(pid), Handle: uintptr(handle), ObjectType: uint16(objType)})
	}
	return out
}

func objectName(handle syscall.Handle) (string, error) {
	size := 1024
	for size <= 1<<20 {
		buf := make([]byte, size)
		need, err := ntQueryObject(handle, objectNameInformation, buf)
		if isLengthMismatch(err) {
			if int(need) > size {
				size = int(need) + 64
			} else {
				size *= 2
			}
			continue
		}
		if err != nil || len(buf) < 16 {
			return "", err
		}
		length := binary.LittleEndian.Uint16(buf[0:2])
		if length < 2 {
			return "", nil
		}
		ptr := uintptr(binary.LittleEndian.Uint64(buf[8:16]))
		base := uintptr(unsafe.Pointer(&buf[0]))
		var raw []byte
		if ptr >= base && ptr+uintptr(length) <= base+uintptr(len(buf)) {
			start := int(ptr - base)
			raw = buf[start : start+int(length)]
		} else if ptr != 0 {
			return "", errors.New("对象名指针不在查询缓冲里")
		} else {
			return "", nil
		}
		chars := make([]uint16, len(raw)/2)
		for i := range chars {
			chars[i] = binary.LittleEndian.Uint16(raw[i*2 : i*2+2])
		}
		return syscall.UTF16ToString(chars), nil
	}
	return "", errors.New("对象名过长")
}

type tableInfo struct {
	mode      handleMode
	typeIndex uint16
}

func detectTable() (tableInfo, error) {
	name := fmt.Sprintf(`Local\WeixinTwin_TypeProbe_%d`, os.Getpid())
	probe, err := createNamed(name)
	if err != nil {
		return tableInfo{}, err
	}
	defer closeHandle(probe)
	myPID := uint32(os.Getpid())
	want := uintptr(probe)

	// The legacy table is the only one whose object-type field stays valid
	// for an elevated process. The extended table reports type 0 for every
	// handle in that case, which makes the singleton mutex unfindable.
	if raw, err := querySystem(systemHandleInformation); err == nil {
		for _, h := range parseLegacy(raw) {
			if h.PID == myPID && h.Handle == (want&0xFFFF) {
				return tableInfo{mode: modeLegacy, typeIndex: h.ObjectType}, nil
			}
		}
	}
	if raw, err := querySystem(systemExtendedHandleInformation); err == nil {
		for _, h := range parseExtended(raw) {
			if h.PID == myPID && h.Handle == want && h.ObjectType != 0 {
				return tableInfo{mode: modeExtended, typeIndex: h.ObjectType}, nil
			}
		}
	}
	return tableInfo{}, errors.New("没能识别互斥体类型")
}

func allHandles(info tableInfo, pids map[uint32]bool) ([]handleEntry, error) {
	var entries []handleEntry
	var err error
	switch info.mode {
	case modeExtended:
		var raw []byte
		raw, err = querySystem(systemExtendedHandleInformation)
		if err != nil {
			return nil, err
		}
		entries = parseExtended(raw)
	case modeLegacy:
		var raw []byte
		raw, err = querySystem(systemHandleInformation)
		if err != nil {
			return nil, err
		}
		entries = parseLegacy(raw)
	default:
		return nil, errors.New("句柄表模式未知")
	}
	if len(pids) == 0 {
		return entries, nil
	}
	var out []handleEntry
	for _, h := range entries {
		if pids[h.PID] {
			out = append(out, h)
		}
	}
	return out, nil
}

func handlesFor(info tableInfo, pids map[uint32]bool) ([]handleEntry, error) {
	var entries []handleEntry
	var err error
	switch info.mode {
	case modeExtended:
		var raw []byte
		raw, err = querySystem(systemExtendedHandleInformation)
		if err != nil {
			return nil, err
		}
		entries = parseExtended(raw)
	case modeLegacy:
		var raw []byte
		raw, err = querySystem(systemHandleInformation)
		if err != nil {
			return nil, err
		}
		entries = parseLegacy(raw)
	default:
		return nil, errors.New("句柄表模式未知")
	}
	var out []handleEntry
	for _, h := range entries {
		if pids[h.PID] && h.ObjectType == info.typeIndex {
			out = append(out, h)
		}
	}
	return out, nil
}

func isSingletonMutex(name string) bool {
	lower := strings.ToLower(name)
	for _, mark := range strings.Split(mutexMarks, ",") {
		if strings.Contains(lower, strings.ToLower(mark)) {
			return true
		}
	}
	return false
}

var closeErrors []string

func closeSingletonMutexes(pids []uint32) (int, []string, error) {
	closeErrors = nil
	if len(pids) == 0 {
		return 0, nil, nil
	}
	info, err := detectTable()
	if err != nil {
		return 0, nil, err
	}
	set := make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		set[pid] = true
	}
	entries, err := handlesFor(info, set)
	if err != nil {
		return 0, nil, err
	}

	closed := 0
	var names []string
	seen := map[[2]uintptr]bool{}
	for _, entry := range entries {
		key := [2]uintptr{uintptr(entry.PID), entry.Handle}
		if seen[key] {
			continue
		}
		seen[key] = true
		proc, err := openProcess(processDupHandle, entry.PID)
		if err != nil {
			continue
		}
		dup, err := duplicateHandle(proc, entry.Handle, queryNameAccess, 0)
		if err != nil || dup == 0 {
			closeHandle(proc)
			continue
		}
		objName, nameErr := objectName(dup)
		if nameErr != nil || objName == "" || !isSingletonMutex(objName) {
			closeHandle(dup)
			closeHandle(proc)
			continue
		}
		// WeChat replaces its own handle as soon as the name is queried, so
		// the value from the snapshot is already stale. Closing our copy
		// closes the kernel object itself.
		closeHandle(dup)
		closeHandle(proc)
		closed++
		names = append(names, objName)
	}
	return closed, names, nil
}

func wechatPIDs() []uint32 {
	procs := listWeChat()
	pids := make([]uint32, 0, len(procs))
	for _, p := range procs {
		pids = append(pids, p.PID)
	}
	return pids
}

func pidSet(list []weProcess) map[uint32]bool {
	m := make(map[uint32]bool, len(list))
	for _, p := range list {
		m[p.PID] = true
	}
	return m
}

func waitNewMain(before map[uint32]bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, p := range mainProcesses() {
			if !before[p.PID] {
				return true
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func startWeChat(exe string) error {
	cmd := exec.Command(exe)
	cmd.Dir = filepath.Dir(exe)
	return cmd.Start()
}

// releaseAndLaunch closes the singleton mutex and starts WeChat before
// returning to the caller. WeChat rebuilds the mutex as soon as it notices
// the gap, so the new process has to be created inside the same pass.
func releaseAndLaunch(exe string) (int, error) {
	pids := wechatPIDs()
	if len(pids) == 0 {
		return 0, errNeedAdmin
	}
	info, err := detectTable()
	if err != nil {
		return 0, err
	}
	set := make(map[uint32]bool, len(pids))
	for _, pid := range pids {
		set[pid] = true
	}
	entries, err := handlesFor(info, set)
	if err != nil {
		return 0, err
	}
	closed := 0
	var launchErr error
	seen := map[[2]uintptr]bool{}
	for _, entry := range entries {
		key := [2]uintptr{uintptr(entry.PID), entry.Handle}
		if seen[key] {
			continue
		}
		seen[key] = true
		proc, err := openProcess(processDupHandle, entry.PID)
		if err != nil {
			continue
		}
		dup, err := duplicateHandle(proc, entry.Handle, queryNameAccess, 0)
		if err != nil || dup == 0 {
			closeHandle(proc)
			continue
		}
		objName, nameErr := objectName(dup)
		if nameErr != nil || objName == "" || !isSingletonMutex(objName) {
			closeHandle(dup)
			closeHandle(proc)
			continue
		}
		closeHandle(dup)
		closeHandle(proc)
		closed++
		if launchErr == nil {
			launchErr = startWeChat(exe)
		}
	}
	if closed == 0 {
		return 0, errNeedAdmin
	}
	return closed, launchErr
}

func shortMutex(name string) string {
	name = strings.ReplaceAll(name, `/`, `\`)
	if i := strings.LastIndex(name, `\`); i >= 0 {
		return name[i+1:]
	}
	return name
}

// OpenAnother releases WeChat's singleton lock, then starts the official client.
// The window that is already open stays open.
func OpenAnother(exe string, count int, log func(string)) error {
	if !fileExists(exe) {
		return errNoWeChat
	}
	if count < 1 {
		count = 1
	}
	if count > 5 {
		count = 5
	}
	enableDebugPrivilege()

	for i := 0; i < count; i++ {
		before := pidSet(mainProcesses())
		if len(before) == 0 {
			log("当前没有微信，先启动第一个。")
			if err := startWeChat(exe); err != nil {
				return fmt.Errorf("启动微信失败：%w", err)
			}
			if !waitNewMain(before, 12*time.Second) {
				return errNoWindow
			}
			time.Sleep(600 * time.Millisecond)
			if n, names, err := closeSingletonMutexes(wechatPIDs()); err != nil {
				return err
			} else if n > 0 {
				log("已放开单实例锁：" + shortMutex(names[0]))
			}
			log(fmt.Sprintf("第 %d 个微信已启动。", i+1))
			continue
		}

		opened := false
		var lastErr error
		for attempt := 1; attempt <= 2 && !opened; attempt++ {
			n, launchErr := releaseAndLaunch(exe)
			if n == 0 {
				lastErr = launchErr
				if launchErr == nil {
					lastErr = errNeedAdmin
				}
				if attempt == 2 {
					return lastErr
				}
				time.Sleep(400 * time.Millisecond)
				continue
			}
			log(fmt.Sprintf("已放开单实例锁 %d 把，正在打开第 %d 个…", n, i+1))
			if launchErr != nil {
				return launchErr
			}
			if waitNewMain(before, 10*time.Second) {
				opened = true
				break
			}
			log("这一次没出现新窗口，再试一次。")
		}
		if lastErr != nil && !opened {
			return lastErr
		}
		if !opened {
			return errNoWindow
		}
		time.Sleep(700 * time.Millisecond)
		_, _, _ = closeSingletonMutexes(wechatPIDs())
		log(fmt.Sprintf("第 %d 个微信已启动。请用另一个微信号扫码。", i+1))
	}
	return nil
}

func describeMutexes(pids []uint32) ([]string, error) {
	info, err := detectTable()
	if err != nil {
		return nil, err
	}
	set := map[uint32]bool{}
	for _, pid := range pids {
		set[pid] = true
	}
	entries, err := handlesFor(info, set)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		proc, err := openProcess(processDupHandle, entry.PID)
		if err != nil {
			continue
		}
		dup, err := duplicateHandle(proc, entry.Handle, queryNameAccess, 0)
		closeHandle(proc)
		if err != nil || dup == 0 {
			continue
		}
		objName, nameErr := objectName(dup)
		closeHandle(dup)
		if nameErr == nil && objName != "" && strings.Contains(strings.ToLower(objName), "mutex") {
			names = append(names, objName)
		}
	}
	return names, nil
}
