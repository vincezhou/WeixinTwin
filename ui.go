package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"unsafe"
)

var (
	user32   = syscall.NewLazyDLL("user32.dll")
	gdi32    = syscall.NewLazyDLL("gdi32.dll")
	comdlg32 = syscall.NewLazyDLL("comdlg32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	procRegisterClassExW   = user32.NewProc("RegisterClassExW")
	procCreateWindowExW    = user32.NewProc("CreateWindowExW")
	procDefWindowProcW     = user32.NewProc("DefWindowProcW")
	procGetMessageW        = user32.NewProc("GetMessageW")
	procTranslateMessage   = user32.NewProc("TranslateMessage")
	procDispatchMessageW   = user32.NewProc("DispatchMessageW")
	procPostQuitMessage    = user32.NewProc("PostQuitMessage")
	procPostMessageW       = user32.NewProc("PostMessageW")
	procSendMessageW       = user32.NewProc("SendMessageW")
	procSetWindowTextW     = user32.NewProc("SetWindowTextW")
	procMessageBoxW        = user32.NewProc("MessageBoxW")
	procLoadCursorW        = user32.NewProc("LoadCursorW")
	procGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW")
	procCreateFontW        = gdi32.NewProc("CreateFontW")
	procSetProcessDPIAware = user32.NewProc("SetProcessDPIAware")
	procGetDpiForSystem    = user32.NewProc("GetDpiForSystem")
	procAdjustWindowRectEx = user32.NewProc("AdjustWindowRectEx")
	procShowWindow         = user32.NewProc("ShowWindow")
	procUpdateWindow       = user32.NewProc("UpdateWindow")
	procGetSystemMetrics   = user32.NewProc("GetSystemMetrics")
	procSetTextColor       = gdi32.NewProc("SetTextColor")
	procSetBkMode          = gdi32.NewProc("SetBkMode")
	procCreateSolidBrush   = gdi32.NewProc("CreateSolidBrush")
	procGetOpenFileNameW   = comdlg32.NewProc("GetOpenFileNameW")
	procEnableWindow       = user32.NewProc("EnableWindow")

	classNamePtr *uint16
	fontUI       uintptr
	fontTitle    uintptr
	fontBold     uintptr
	fontSmall    uintptr
	whiteBrush   uintptr

	hwndMain  uintptr
	hwndTitle uintptr
	hwndPath  uintptr
	hwndVer   uintptr
	hwndState uintptr
	hwndLog   uintptr
	hwndOpen  uintptr
	hwndAdmin uintptr
	softText  []uintptr

	uiOnce     sync.Once
	logMu      sync.Mutex
	logQ       []string
	pendingMu  sync.Mutex
	pendingErr string
	busy       bool
	exeNow     string
	statusMu   sync.Mutex
	statusSeq  uint64
	statusNext uiStatus
)

const (
	wsOverlapped   = 0x00000000
	wsCaption      = 0x00C00000
	wsSysMenu      = 0x00080000
	wsMinimizeBox  = 0x00020000
	wsVisible      = 0x10000000
	wsChild        = 0x40000000
	wsClipChildren = 0x02000000
	wsTabStop      = 0x00010000
	wsVScroll      = 0x00200000

	esMultiline   = 0x0004
	esReadOnly    = 0x0800
	esAutoVScroll = 0x0040

	bsDefPushButton = 0x00000001
	bsPushButton    = 0x00000000
	bsGroupBox      = 0x00000007

	ssCenterImage  = 0x00000200
	ssEndEllipsis  = 0x00004000
	ssPathEllipsis = 0x00008000
	ssNoPrefix     = 0x00000080

	wmDestroy        = 0x0002
	wmClose          = 0x0010
	wmCommand        = 0x0111
	wmSetFont        = 0x0030
	wmCtlColorStatic = 0x0138
	wmCtlColorBtn    = 0x0135
	wmAppLog         = 0x8000 + 1
	wmAppRefresh     = 0x8000 + 2
	wmAppStatus      = 0x8000 + 3

	idOpen  = 101
	idPick  = 102
	idAdmin = 103

	swShow      = 5
	colorWindow = 5

	mbIconWarning = 0x30
	mbIconError   = 0x10
	mbOK          = 0x00
)

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   uintptr
	Icon       uintptr
	Cursor     uintptr
	Background uintptr
	MenuName   *uint16
	ClassName  *uint16
	IconSm     uintptr
}

type point struct{ X, Y int32 }
type rect struct{ Left, Top, Right, Bottom int32 }
type msg struct {
	HWND    uintptr
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      point
}

type openFileName struct {
	StructSize      uint32
	Owner           uintptr
	Instance        uintptr
	Filter          *uint16
	CustomFilter    *uint16
	MaxCustomFilter uint32
	FilterIndex     uint32
	File            *uint16
	MaxFile         uint32
	FileTitle       *uint16
	MaxFileTitle    uint32
	InitialDir      *uint16
	Title           *uint16
	Flags           uint32
	FileOffset      uint16
	FileExtension   uint16
	DefExt          *uint16
	CustData        uintptr
	FnHook          uintptr
	TemplateName    *uint16
	PvReserved      uintptr
	DwReserved      uint32
	FlagsEx         uint32
}

func utf16(s string) *uint16 {
	p, err := syscall.UTF16PtrFromString(s)
	if err != nil {
		p, _ = syscall.UTF16PtrFromString("")
	}
	return p
}

func scale(px int) int {
	dpi, _, _ := procGetDpiForSystem.Call()
	if dpi < 96 {
		dpi = 96
	}
	return px * int(dpi) / 96
}

func createFont(height, weight int, face string) uintptr {
	h, _, _ := procCreateFontW.Call(
		uintptr(uint32(-scale(height))),
		0, 0, 0,
		uintptr(weight),
		0, 0, 0,
		1, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(utf16(face))),
	)
	return h
}

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch msg {
	case wmCommand:
		switch wparam & 0xFFFF {
		case idOpen:
			onOpen()
		case idPick:
			onPick()
		case idAdmin:
			onAdmin()
		}
		return 0
	case wmAppLog:
		flushLog()
		return 0
	case wmAppRefresh:
		busy = false
		setText(hwndOpen, "再开一个")
		procEnableWindow.Call(hwndOpen, 1)
		requestStatusRefresh()
		pendingMu.Lock()
		errText := pendingErr
		pendingErr = ""
		pendingMu.Unlock()
		if errText != "" {
			message("WeixinTwin 微信多开", errText, mbIconWarning)
		}
		return 0
	case wmAppStatus:
		applyPendingStatus()
		return 0
	case wmCtlColorStatic:
		hdc := wparam
		procSetBkMode.Call(hdc, 1)
		switch {
		case lparam == hwndState:
			procSetTextColor.Call(hdc, 0x00221610)
		case isSoft(lparam):
			procSetTextColor.Call(hdc, 0x00808080)
		default:
			procSetTextColor.Call(hdc, 0x00332211)
		}
		return whiteBrush
	case wmDestroy:
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProcW.Call(hwnd, msg, wparam, lparam)
	return r
}

var wndProcCB uintptr

func runUI() {
	// Win32 windows and their message queues belong to the OS thread that
	// created them. A Go goroutine may otherwise move between OS threads,
	// leaving GetMessage waiting on a different (empty) queue forever.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	initCOM()
	procSetProcessDPIAware.Call()
	whiteBrush, _, _ = procCreateSolidBrush.Call(0x00FFFFFF)
	fontTitle = createFont(22, 700, "Microsoft YaHei UI")
	fontBold = createFont(16, 600, "Microsoft YaHei UI")
	fontUI = createFont(14, 400, "Microsoft YaHei UI")
	fontSmall = createFont(12, 400, "Microsoft YaHei UI")

	inst, _, _ := procGetModuleHandleW.Call(0)
	cursor, _, _ := procLoadCursorW.Call(0, 32512) // IDC_ARROW
	classNamePtr = utf16("WeixinTwinWindow")
	wndProcCB = syscall.NewCallback(wndProc)

	wc := wndClassEx{
		WndProc:    wndProcCB,
		Instance:   inst,
		Cursor:     cursor,
		Background: colorWindow + 1,
		ClassName:  classNamePtr,
	}
	wc.Size = uint32(unsafe.Sizeof(wc))
	atom, _, err := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if atom == 0 {
		fatalBox("窗口注册失败：" + err.Error())
		return
	}

	width, height := scale(500), scale(470)
	var rc rect
	rc.Right = int32(width)
	rc.Bottom = int32(height)
	style := uintptr(wsOverlapped | wsCaption | wsSysMenu | wsMinimizeBox | wsClipChildren)
	procAdjustWindowRectEx.Call(uintptr(unsafe.Pointer(&rc)), style, 0, 0)
	winW := int(rc.Right - rc.Left)
	winH := int(rc.Bottom - rc.Top)
	screenW, _, _ := procGetSystemMetrics.Call(0)
	screenH, _, _ := procGetSystemMetrics.Call(1)
	x := (int(screenW) - winW) / 2
	y := (int(screenH) - winH) / 2

	hwndMain, _, _ = procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(classNamePtr)),
		uintptr(unsafe.Pointer(utf16("WeixinTwin 微信多开"))),
		style,
		uintptr(x), uintptr(y), uintptr(winW), uintptr(winH),
		0, 0, inst, 0,
	)
	if hwndMain == 0 {
		fatalBox("窗口创建失败")
		return
	}

	buildControls(inst)
	appendLog("准备好了。微信已经开着的话，直接点「再开一个」。")

	procShowWindow.Call(hwndMain, swShow)
	procUpdateWindow.Call(hwndMain)
	requestStatusRefresh()

	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func isSoft(hwnd uintptr) bool {
	for _, h := range softText {
		if h == hwnd {
			return true
		}
	}
	return false
}

func staticStyled(inst uintptr, text string, x, y, w, h int, font, extra uintptr) uintptr {
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16("STATIC"))),
		uintptr(unsafe.Pointer(utf16(text))),
		uintptr(wsChild|wsVisible)|extra,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hwndMain, 0, inst, 0,
	)
	procSendMessageW.Call(hwnd, wmSetFont, font, 1)
	return hwnd
}

func label(inst uintptr, text string, x, y, w, h int) uintptr {
	hwnd := staticStyled(inst, text, x, y, w, h, fontSmall, ssCenterImage)
	softText = append(softText, hwnd)
	return hwnd
}

func button(inst uintptr, text string, id, x, y, w, h int, font uintptr, def bool) uintptr {
	style := uintptr(wsChild | wsVisible | wsTabStop | bsPushButton)
	if def {
		style = uintptr(wsChild | wsVisible | wsTabStop | bsDefPushButton)
	}
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16("BUTTON"))),
		uintptr(unsafe.Pointer(utf16(text))),
		style,
		uintptr(x), uintptr(y), uintptr(w), uintptr(h),
		hwndMain, uintptr(id), inst, 0,
	)
	procSendMessageW.Call(hwnd, wmSetFont, font, 1)
	return hwnd
}

func fieldRow(inst uintptr, title string, x, y, labelW, valueW, h int, valueFont, extra uintptr) uintptr {
	label(inst, title, x, y, labelW, h)
	return staticStyled(inst, "…", x+labelW, y, valueW, h, valueFont, ssCenterImage|ssNoPrefix|extra)
}

func buildControls(inst uintptr) {
	m := scale(24)
	width := scale(500) - m*2
	y := scale(18)

	groupH := scale(132)
	group, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(utf16("BUTTON"))),
		uintptr(unsafe.Pointer(utf16("当前微信"))),
		uintptr(wsChild|wsVisible|bsGroupBox),
		uintptr(m), uintptr(y), uintptr(width), uintptr(groupH),
		hwndMain, 0, inst, 0,
	)
	procSendMessageW.Call(group, wmSetFont, fontSmall, 1)
	softText = append(softText, group)

	rowX := m + scale(16)
	rowW := width - scale(32)
	labelW := scale(44)
	valueW := rowW - labelW
	rowH := scale(26)
	iy := y + scale(26)
	hwndState = fieldRow(inst, "状态", rowX, iy, labelW, valueW, rowH, fontBold, 0)
	iy += scale(30)
	hwndVer = fieldRow(inst, "版本", rowX, iy, labelW, valueW, rowH, fontUI, 0)
	iy += scale(30)
	hwndPath = fieldRow(inst, "路径", rowX, iy, labelW, valueW, rowH, fontSmall, ssPathEllipsis)
	y += groupH + scale(16)

	hwndOpen = button(inst, "再开一个", idOpen, m, y, width, scale(40), fontBold, true)
	y += scale(50)

	gap := scale(10)
	half := (width - gap) / 2
	button(inst, "选择微信", idPick, m, y, half, scale(32), fontUI, false)
	hwndAdmin = button(inst, "以管理员身份运行", idAdmin, m+half+gap, y, half, scale(32), fontUI, false)
	y += scale(46)

	rec := staticStyled(inst, "记录", m, y, width, scale(18), fontSmall, 0)
	softText = append(softText, rec)
	y += scale(22)
	hwndLog, _, _ = procCreateWindowExW.Call(
		0x200, // WS_EX_CLIENTEDGE
		uintptr(unsafe.Pointer(utf16("EDIT"))),
		0,
		wsChild|wsVisible|wsVScroll|esMultiline|esReadOnly|esAutoVScroll,
		uintptr(m), uintptr(y), uintptr(width), uintptr(scale(132)),
		hwndMain, 0, inst, 0,
	)
	procSendMessageW.Call(hwndLog, wmSetFont, fontSmall, 1)
	y += scale(142)
	foot := staticStyled(inst, "新窗口要用另一个微信号扫码。只在自己的电脑上用。", m, y, width, scale(20), fontSmall, ssEndEllipsis)
	softText = append(softText, foot)
}

func setText(hwnd uintptr, text string) {
	procSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(utf16(text))))
}

type uiStatus struct {
	seq       uint64
	exe       string
	version   string
	mainCount int
	admin     bool
}

func requestStatusRefresh() {
	statusMu.Lock()
	statusSeq++
	seq := statusSeq
	statusMu.Unlock()
	hwnd := hwndMain
	go func() {
		exe := discoverExe()
		version := "—"
		if exe != "" {
			version = wechatVersion(exe)
		}
		status := uiStatus{
			seq:       seq,
			exe:       exe,
			version:   version,
			mainCount: len(mainProcesses()),
			admin:     isAdmin(),
		}
		statusMu.Lock()
		if seq != statusSeq {
			statusMu.Unlock()
			return
		}
		statusNext = status
		statusMu.Unlock()
		procPostMessageW.Call(hwnd, wmAppStatus, 0, 0)
	}()
}

func applyPendingStatus() {
	statusMu.Lock()
	status := statusNext
	current := statusSeq
	statusMu.Unlock()
	if status.seq == 0 || status.seq != current {
		return
	}
	exeNow = status.exe
	if exeNow == "" {
		setText(hwndPath, "没找到，请点「选择微信」")
		setText(hwndVer, "—")
	} else {
		setText(hwndPath, exeNow)
		setText(hwndVer, status.version)
	}
	switch status.mainCount {
	case 0:
		setText(hwndState, "还没打开。点按钮会先启动第一个")
	case 1:
		setText(hwndState, "已经开着 1 个，可以再开一个")
	default:
		setText(hwndState, fmt.Sprintf("已经开着 %d 个主窗口", status.mainCount))
	}
	if status.admin {
		procShowWindow.Call(hwndAdmin, 0)
	}
}

func appendLog(line string) {
	logMu.Lock()
	logQ = append(logQ, line)
	logMu.Unlock()
	if hwndMain != 0 {
		procPostMessageW.Call(hwndMain, wmAppLog, 0, 0)
	}
}

func flushLog() {
	logMu.Lock()
	lines := logQ
	logQ = nil
	logMu.Unlock()
	if len(lines) == 0 || hwndLog == 0 {
		return
	}
	const emSetSel = 0x00B1
	const emReplaceSel = 0x00C2
	for _, line := range lines {
		text := line + "\r\n"
		procSendMessageW.Call(hwndLog, emSetSel, ^uintptr(0), ^uintptr(0))
		procSendMessageW.Call(hwndLog, emReplaceSel, 0, uintptr(unsafe.Pointer(utf16(text))))
	}
}

func onOpen() {
	if busy {
		return
	}
	if exeNow == "" || !fileExists(exeNow) {
		message("WeixinTwin", "没有找到微信。请先安装，或点「选择微信」。", mbIconWarning)
		return
	}
	saveExe(exeNow)
	busy = true
	setText(hwndOpen, "正在打开…")
	procEnableWindow.Call(hwndOpen, 0)
	exe := exeNow
	go func() {
		err := OpenAnother(exe, 1, appendLog)
		if err != nil {
			appendLog(err.Error())
			pendingMu.Lock()
			pendingErr = err.Error()
			pendingMu.Unlock()
		}
		procPostMessageW.Call(hwndMain, wmAppRefresh, 0, 0)
	}()
}

func onPick() {
	buf := make([]uint16, 520)
	title := utf16("选择微信主程序")
	filter := utf16("微信主程序\x00Weixin.exe;WeChat.exe\x00可执行文件\x00*.exe\x00\x00")
	ofn := openFileName{
		Owner:   hwndMain,
		Filter:  filter,
		File:    &buf[0],
		MaxFile: uint32(len(buf)),
		Title:   title,
		Flags:   0x00001000 | 0x00000800, // FILEMUSTEXIST | PATHMUSTEXIST
	}
	ofn.StructSize = uint32(unsafe.Sizeof(ofn))
	ok, _, _ := procGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ok == 0 {
		return
	}
	path := syscall.UTF16ToString(buf)
	if path == "" {
		return
	}
	saveExe(path)
	exeNow = path
	requestStatusRefresh()
	appendLog("已改用 " + path)
}

func onAdmin() {
	if isAdmin() {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		message("WeixinTwin", "找不到自己的程序路径", mbIconError)
		return
	}
	verb := utf16("runas")
	file := utf16(exe)
	r, _, _ := syscall.NewLazyDLL("shell32.dll").NewProc("ShellExecuteW").Call(
		0,
		uintptr(unsafe.Pointer(verb)),
		uintptr(unsafe.Pointer(file)),
		0, 0, 1,
	)
	if r <= 32 {
		message("WeixinTwin", "没有获得管理员权限", mbIconWarning)
		return
	}
	procPostQuitMessage.Call(0)
}

func message(title, text string, flags uintptr) {
	procMessageBoxW.Call(hwndMain, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16(title))), flags|mbOK)
}

func fatalBox(text string) {
	procMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16("WeixinTwin"))), mbOK|mbIconError)
}
