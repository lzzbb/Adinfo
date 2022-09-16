// Helper functions

package goddi

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// WindowsEpochFiletime January 1, 1601 UTC (coordinate universal time)
const WindowsEpochFiletime int64 = 116444736000000000

// Writing output to csv
// Reference: https://golangcode.com/write-data-to-a-csv-file/
func writeCSV(filename string, data [][]string) {

	cwd := GetCWD()
	csvdir := cwd + "/csv/"
	if _, err := os.Stat(csvdir); os.IsNotExist(err) {
		os.Mkdir(csvdir, os.ModePerm)
	}

	file, err := os.Create(csvdir + filename + ".csv")

	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	for _, value := range data {
		err := writer.Write(value)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// Get sub directories
func getSubDirs(drive string) []string {

	file, err := os.Open(drive)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	list, _ := file.Readdirnames(0)
	return list
}

// GetCWD returns executable's current directory
func GetCWD() string {

	exe, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	cwd := filepath.Dir(exe)
	return cwd
}

// Helper function to decrypt GPP cpassword
// References:
// https://github.com/leonteale/pentestpackage/blob/master/Gpprefdecrypt.py
// https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
func decrypt(cpassword string) string {

	// 32 byte AES key
	// http://msdn.microsoft.com/en-us/library/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be%28v=PROT.13%29#endNote2
	key := "4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b"

	// hex decode the key
	decoded, _ := hex.DecodeString(key)
	block, err := aes.NewCipher(decoded)
	if err != nil {
		log.Fatal(err)
	}

	// add padding to base64 cpassword if necessary
	m := len(cpassword) % 4
	if m != 0 {
		cpassword += strings.Repeat("=", 4-m)
	}

	// base64 decode cpassword
	decodedpassword, errs := base64.StdEncoding.DecodeString(cpassword)
	if errs != nil {
		log.Fatal(errs)
	}

	if len(decodedpassword) < aes.BlockSize {
		log.Fatal("Cpassword block size too short...\n")
	}

	var iv = []byte{00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00}

	if (len(decodedpassword) % aes.BlockSize) != 0 {
		log.Fatal("Blocksize must be multiple of decoded message length...\n")
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decodedpassword, decodedpassword)

	// remove the padding at the end of password
	length := len(decodedpassword)
	unpadding := int(decodedpassword[length-1])
	clear := decodedpassword[:(length - unpadding)]

	return string(clear)
}

// Converts ldap password age
func convertPwdAge(pwdage string) string {

	f, _ := strconv.ParseFloat((strings.Replace(pwdage, "-", "", -1)), 64)
	age := ((f / (60 * 10000000)) / 60) / 24
	flr := math.Floor(age)
	s := strconv.Itoa(int(flr))

	return s
}

// Convers ldap lockout
func convertLockout(lockout string) string {

	i, _ := strconv.Atoi(strings.Replace(lockout, "-", "", -1))
	age := i / (60 * 10000000)
	s := strconv.Itoa(age)

	return s
}

func ConvertLDAPTime(t int) time.Time {
	LDAPtime := t
	winSecs := LDAPtime / 10000000
	timeStamp := winSecs - 11644473600
	return time.Unix(int64(timeStamp), 0)
}

func wordLE(arr []byte, index int) byte {
	//wordLE([4 0 1 0 5 240 0 0 178 3 0 0 0 0 2 88 0 0 0 0 241 73 56 0 192 168 200 207],2)
	find := int(arr[index+1])*256 + int(arr[index])
	return byte(find)
}

func processDnsRecordAttribute(record []byte) []byte {
	//record=[4 0 1 0 5 240 0 0 178 3 0 0 0 0 2 88 0 0 0 0 241 73 56 0 192 168 200 207]
	var rdatatype = wordLE(record, 2)
	if rdatatype == 1 {
		a := []byte{record[24], record[25], record[26], record[27]}
		return a
	}
	return nil
}

// https://stackoverflow.com/questions/24836044/case-insensitive-string-search-in-golang
func  caseInsensitiveContains(s, substr string) bool {
	return strings.Contains(strings.ToUpper(s), strings.ToUpper(substr))
}

// ValidateIPHostname parses and returns hostname and ip for dc
/*
func ValidateIPHostname(ldapServer string, domain string) (string, string) {
	var ldapIP string
	//ldapServer=192.168.129.10
	//ParseIP=192.168.129.10
	if net.ParseIP(ldapServer) != nil {
		ldapIP = ldapServer
		hostnames, err := net.LookupAddr(ldapServer)
		//LookupAddr查找dns解析记录
		//hostnames=dc1.redteam.lab
		if err != nil {
			log.Fatal(err)
		}
		for _, host := range hostnames {
			//host=dc1.redteam.lab
			//domain=redteam.lab
			if caseInsensitiveContains(host, domain) {
				ldapServer = strings.Trim(host, ".")
				//ldapServer=redteam.lab
			}
		}
	} else {
		//ldapServer=dc1.redteam.lab
		addr, err := net.LookupIP(ldapServer)
		//net.LookupIP寻找A记录
		if err != nil {
			log.Fatal(err)
		}
		ldapIP = addr[0].String()
	}
	return ldapServer, ldapIP
}

*/

func tcpGather(ip string, ports []string) map[string]string {
	// check emqx 1883, 8083 port

	results := make(map[string]string)
	for _, port := range ports {
		address := net.JoinHostPort(ip, port)
		// 3 second timeout
		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			results[port] ="failed"
			// todo log handler
		} else {
			if conn != nil {
				results[port] ="success"
				_ = conn.Close()
			} else {
				results[port] ="failed"
			}
		}
	}
	return results
}