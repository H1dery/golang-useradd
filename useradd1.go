package main

import (
    "fmt"
    "syscall"
    "unsafe"
    "os"
    "strings"

)
var (
    modNetapi32                = syscall.NewLazyDLL("netapi32.dll")
    usrNetUserAdd              = modNetapi32.NewProc("NetUserAdd")
    usrNetUserSetInfo          = modNetapi32.NewProc("NetUserSetInfo")
    usrNetLocalGroupAddMembers = modNetapi32.NewProc("NetLocalGroupAddMembers")


)

type LOCALGROUP_MEMBERS_INFO_3 struct {
    Lgrmi3_domainandname *uint16
}

type USER_INFO_1 struct {
    Usri1_name         *uint16
    Usri1_password     *uint16
    Usri1_password_age uint32
    Usri1_priv         uint32
    Usri1_home_dir     *uint16
    Usri1_comment      *uint16
    Usri1_flags        uint32
    Usri1_script_path  *uint16
}
type USER_INFO_1011 struct {
    Usri1011_full_name *uint16
}
const (
    NET_API_STATUS_NERR_Success                      = 0
    NET_API_STATUS_NERR_InvalidComputer              = 2351
    NET_API_STATUS_NERR_NotPrimary                   = 2226
    NET_API_STATUS_NERR_SpeGroupOp                   = 2234
    NET_API_STATUS_NERR_LastAdmin                    = 2452
    NET_API_STATUS_NERR_BadPassword                  = 2203
    NET_API_STATUS_NERR_PasswordTooShort             = 2245
    NET_API_STATUS_NERR_UserNotFound                 = 2221
    NET_API_STATUS_ERROR_ACCESS_DENIED               = 5
    NET_API_STATUS_ERROR_NOT_ENOUGH_MEMORY           = 8
    NET_API_STATUS_ERROR_INVALID_PARAMETER           = 87
    NET_API_STATUS_ERROR_INVALID_NAME                = 123
    NET_API_STATUS_ERROR_INVALID_LEVEL               = 124
    NET_API_STATUS_ERROR_MORE_DATA                   = 234
    NET_API_STATUS_ERROR_SESSION_CREDENTIAL_CONFLICT = 1219
    NET_API_STATUS_RPC_S_SERVER_UNAVAILABLE          = 2147944122
    NET_API_STATUS_RPC_E_REMOTE_DISABLED             = 2147549468

    USER_PRIV_MASK  = 0x3
    USER_PRIV_GUEST = 0
    USER_PRIV_USER  = 1
    USER_PRIV_ADMIN = 2

    USER_FILTER_NORMAL_ACCOUNT = 0x0002
    USER_MAX_PREFERRED_LENGTH  = 0xFFFFFFFF

    USER_UF_SCRIPT             = 1
    USER_UF_ACCOUNTDISABLE     = 2
    USER_UF_LOCKOUT            = 16
    USER_UF_PASSWD_CANT_CHANGE = 64
    USER_UF_NORMAL_ACCOUNT     = 512
    USER_UF_DONT_EXPIRE_PASSWD = 65536
)
type UserAddOptions struct {
    // Required
    Username string
    Password string

    // Optional
    FullName   string
    PrivLevel  uint32
    HomeDir    string
    Comment    string
    ScriptPath string
}
func UserAddEx(opts UserAddOptions) (bool, error) {
    var parmErr uint32
    var err error
    uInfo := USER_INFO_1{
        Usri1_priv:  opts.PrivLevel,
        Usri1_flags: USER_UF_SCRIPT | USER_UF_NORMAL_ACCOUNT | USER_UF_DONT_EXPIRE_PASSWD,
    }
    uInfo.Usri1_name, err = syscall.UTF16PtrFromString(opts.Username)
    if err != nil {
        return false, fmt.Errorf("Unable to encode username to UTF16: %s", err)
    }
    uInfo.Usri1_password, err = syscall.UTF16PtrFromString(opts.Password)
    if err != nil {
        return false, fmt.Errorf("Unable to encode password to UTF16: %s", err)
    }
    if opts.Comment != "" {
        uInfo.Usri1_comment, err = syscall.UTF16PtrFromString(opts.Comment)
        if err != nil {
            return false, fmt.Errorf("Unable to encode comment to UTF16: %s", err)
        }
    }
    if opts.HomeDir != "" {
        uInfo.Usri1_home_dir, err = syscall.UTF16PtrFromString(opts.HomeDir)
        if err != nil {
            return false, fmt.Errorf("Unable to encode home directory path to UTF16: %s", err)
        }
    }
    if opts.ScriptPath != "" {
        uInfo.Usri1_script_path, err = syscall.UTF16PtrFromString(opts.HomeDir)
        if err != nil {
            return false, fmt.Errorf("Unable to encode script path to UTF16: %s", err)
        }
    }
    ret, _, _ := usrNetUserAdd.Call(
        uintptr(0),
        uintptr(uint32(1)),
        uintptr(unsafe.Pointer(&uInfo)),
        uintptr(unsafe.Pointer(&parmErr)),
    )
    if ret != NET_API_STATUS_NERR_Success {
        return false, fmt.Errorf("Unable to process: status=%d error=%d", ret, parmErr)
    }
    if opts.FullName != "" {
        ok, err := UserUpdateFullname(opts.Username, opts.FullName)
        if err != nil {
            return false, fmt.Errorf("Unable to set full name: %s", err)
        }
        if !ok {
            return false, fmt.Errorf("Problem while setting Full Name")
        }
    }

    return AddGroupMembership(opts.Username, "Users")
}


func UserAdd(username string, fullname string, password string) (bool, error) {
    return UserAddEx(UserAddOptions{
        Username:  username,
        Password:  password,
        FullName:  fullname,
        PrivLevel: USER_PRIV_USER,
    })
}

func UserUpdateFullname(username string, fullname string) (bool, error) {
    var errParam uint32
    uPointer, err := syscall.UTF16PtrFromString(username)
    if err != nil {
        return false, fmt.Errorf("unable to encode username to UTF16")
    }
    fPointer, err := syscall.UTF16PtrFromString(fullname)
    if err != nil {
        return false, fmt.Errorf("unable to encode full name to UTF16")
    }
    ret, _, _ := usrNetUserSetInfo.Call(
        uintptr(0),                        // servername
        uintptr(unsafe.Pointer(uPointer)), // username
        uintptr(uint32(1011)),             // level
        uintptr(unsafe.Pointer(&USER_INFO_1011{Usri1011_full_name: fPointer})),
        uintptr(unsafe.Pointer(&errParam)),
    )
    if ret != NET_API_STATUS_NERR_Success {
        return false, fmt.Errorf("unable to process. %d", ret)
    }
    return true, nil
}
func AddGroupMembership(username, groupname string) (bool, error) {
    hn, _ := os.Hostname()
    uPointer, err := syscall.UTF16PtrFromString(hn + `\` + username)
    if err != nil {
        return false, fmt.Errorf("Unable to encode username to UTF16")
    }
    gPointer, err := syscall.UTF16PtrFromString(groupname)
    if err != nil {
        return false, fmt.Errorf("unable to encode group name to UTF16")
    }
    var uArray = make([]LOCALGROUP_MEMBERS_INFO_3, 1)
    uArray[0] = LOCALGROUP_MEMBERS_INFO_3{
        Lgrmi3_domainandname: uPointer,
    }
    ret, _, _ := usrNetLocalGroupAddMembers.Call(
        uintptr(0),                          // servername
        uintptr(unsafe.Pointer(gPointer)),   // group name
        uintptr(uint32(3)),                  // level
        uintptr(unsafe.Pointer(&uArray[0])), // user array.
        uintptr(uint32(len(uArray))),
    )
    if ret != NET_API_STATUS_NERR_Success {
        return false, fmt.Errorf("unable to process. %d", ret)
    }
    return true, nil
}


func LocalGroupAddMembers(groupname string, usernames []string) (bool, error) {
    return localGroupModMembers(usrNetLocalGroupAddMembers, groupname, usernames)
}

func localGroupModMembers(proc *syscall.LazyProc, groupname string, usernames []string) (bool, error) {
    memberInfos := make([]LOCALGROUP_MEMBERS_INFO_3, 0, len(usernames))
    hostname, err := os.Hostname()
    if err != nil {
        return false, fmt.Errorf("Unable to determine hostname: %s", err)
    }
    groupnamePtr, err := syscall.UTF16PtrFromString(groupname)
    if err != nil {
        return false, fmt.Errorf("Unable to encode group name to UTF16: %s", err)
    }

    for _, username := range usernames {
        domainAndUsername := username
        if !strings.ContainsRune(username, '\\') {
            domainAndUsername = fmt.Sprintf(`%s\%s`, hostname, username)
        }
        namePtr, err := syscall.UTF16PtrFromString(domainAndUsername)
        if err != nil {
            return false, fmt.Errorf("Unable to encode username to UTF16: %s", err)
        }
        memberInfos = append(memberInfos, LOCALGROUP_MEMBERS_INFO_3{
            Lgrmi3_domainandname: namePtr,
        })
    }

    if len(memberInfos) == 0 {
        // Add a fake entry just so that the slice isn't empty, so we can take
        // the address of the first entry
        memberInfos = append(memberInfos, LOCALGROUP_MEMBERS_INFO_3{})
    }

    ret, _, _ := proc.Call(
        uintptr(0),                               // servername
        uintptr(unsafe.Pointer(groupnamePtr)),    // group name
        uintptr(3),                               // level, LOCALGROUP_MEMBERS_INFO_3
        uintptr(unsafe.Pointer(&memberInfos[0])), // buf
        uintptr(len(usernames)),                  // totalEntries
    )
    if ret != NET_API_STATUS_NERR_Success {
        return false, syscall.Errno(ret)
    }

    return true, nil
}


func main(){
    username := "caisi123"
    password := "abc.123"
    fullname := ""
    groupname := "administrators"
    groupuser := []string{"caisi123"}
    UserAdd(username, fullname, password)
    LocalGroupAddMembers(groupname,groupuser)

    //users, err := wapi.ListLocalUsers()
}
