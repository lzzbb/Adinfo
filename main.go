package main

import (
	goddi "example.com/goddi/ddi"
	"fmt"
	"github.com/spf13/pflag"
	"os"
	"strings"
	"time"
)

const logo = `
           _____  _        __
     /\   |  __ \(_)      / _|
    /  \  | |  | |_ _ __ | |_ ___
   / /\ \ | |  | | | '_ \|  _/ _ \     Tools that collect information from domain
  / ____ \| |__| | | | | | || (_) |
 /_/    \_\_____/|_|_| |_|_| \___/     v1.4 by lzz

`

func main() {
	fmt.Printf(logo)
	ldapServer := pflag.String("dc", "", "DC to connect to, use IP or full hostname example: -dc=\"dcip\"")
	domain := pflag.StringP("domain", "d","", "domain example: -domain=\"redteam.lab\"")
	user := pflag.StringP("username", "u", "","username to connect with example: -username=\"user1\"")
	hash := pflag.StringP("hash", "H","", "hash to connect with example: -hash=\"32ed87bdb5fdc5e9cba88547376818d4\"")
	pass := pflag.StringP("password", "p", "","password to connect with example: -password=\"pass1\"")
	unsafe := pflag.Bool("unsafe", true, "Use account password link")
	startTLS := pflag.Bool("startTLS", false, "Use for StartTLS on 389. Default is TLS on 636\n")
	getPolicy := pflag.Bool("getPolicy", false, "get domain Policy")
	getDCandExchangeDNS := pflag.Bool("getDCandExchangeDNS", false, "get DC and Exchange DNS")
	getAllDNS := pflag.Bool("getAllDNS", false, "get all domain DNS")
	getmaq := pflag.Bool("getmaq", false, "get domain MAQ")
	getdomainVersion := pflag.Bool("getdomainVersion", false, "get domain Version")
	getMail := pflag.Bool("getMail", false, "get domain Mail")
	getSID := pflag.Bool("getSID", false, "get domain SID")
	getExchangeInformation := pflag.Bool("getExchangeInformation", false, "get Exchange Information")
	getDomainTrusts := pflag.Bool("getDomainTrusts", false, "get trusts domain")
	getSPN := pflag.Bool("getSPN", false, "get all SPN")
	getGPO := pflag.Bool("getGPO", false, "get all GPO")
	getDomainAdmins := pflag.Bool("getDomainAdmins", false, "get all domain admins")
	dclocaladministrators := pflag.Bool("dclocaladministrators", false, "get dc local administrators")
	BackupOperators := pflag.Bool("BackupOperators", false, "get dc local Backup Operators")
	getDC := pflag.Bool("getDC", false, "get all DomainControllers")
	getAllUser := pflag.Bool("getAllUser", false, "get all domain user")
	getUsefulUserName := pflag.Bool("getUsefulUserName", false, "get all not Disabled and Locked user(only name)")
	getHighlevelUser := pflag.Bool("getHighlevelUser", false, "get users that admincount=1(only name)")
	getNotusefulUser := pflag.Bool("getNotusefulUser", false, "get not useful user(Locked or Disabled)")
	getUsersNoExpire := pflag.Bool("getUsersNoExpire", false, "get users not expire")
	getComputers := pflag.Bool("getComputers", false, "get all domain computers")
	getComputersName := pflag.Bool("getComputersName", false, "get all domain computers(only name)")
	getDomainGroup := pflag.Bool("getDomainGroup", false, "get all domain group")
	getCreatorSID := pflag.Bool("getCreatorSID", false, "get all CreatorSID")
	getADCS := pflag.Bool("getADCS", false, "get ADCS information")
	getOU := pflag.Bool("getOU", false, "get domain OU")
	checkLAPS := pflag.Bool("checkLAPS", false, "get is have LAPS, If the current user has permission, all LAPS passwords will be exported.")
	checkbackdoor := pflag.Bool("checkbackdoor", false, "check backdoor：MAQ、AsReproast、SIDHistory、GetRBCD、UnconstrainedDeligation、ConstrainedDeligation、SensitiveDelegateAccount")
	Krbtgttime := pflag.Bool("Krbtgttime", false, "get Krbtgt password last set time ")

	pflag.CommandLine.SortFlags=false
	pflag.Parse()

	if len(*ldapServer) == 0 || len(*domain) == 0 || len(*user) == 0 {
		fmt.Printf("[-] domain、dc、username、(pass/hash) must provide\n\n")
		os.Exit(1)
	}
	if len(*pass) == 0 && len(*hash) == 0 {
		fmt.Printf("[-] pass or hash must provide\n\n")
		os.Exit(1)
	}

	//var ldapIP string
	//*ldapServer, ldapIP = goddi.ValidateIPHostname(*ldapServer, *domain)

	baseDN := "dc=" + strings.Replace(*domain, ".", ",dc=", -1)
	GetSchemaNamingContextEntry :="CN=Schema,CN=Configuration,"+baseDN
	GetConfigurationContextEntry :="CN=Configuration,"+baseDN
	username := *user + "@" + *domain
	//username:=*user

	var ishash bool
	if len(*pass) == 0 {
		username=*user
		ishash = true
	}else {
		username = *user + "@" + *domain
		ishash = false
	}

	li := &goddi.LdapInfo{
		LdapServer:  *ldapServer,
		LdapIP:      *ldapServer,
		LdapPort:    uint16(389),
		LdapTLSPort: uint16(636),
		User:        username,
		Usergpp:     *user,
		Hash:		 *hash,
		Pass:        *pass,
		Domain:      *domain,
		Unsafe:      *unsafe,
		StartTLS:    *startTLS}

	goddi.Connect(li,ishash)
	defer li.Conn.Close()
	start := time.Now()

	if (*getDCandExchangeDNS) == true {
		goddi.GetDomainControllers(li.Conn, baseDN)
		goddi.GetExchangeServerVersion(li.Conn, GetConfigurationContextEntry)
		goddi.DC_and_Exchange_DNS(li.Conn, "DC="+*domain+",CN=MicrosoftDNS,DC=DomainDnsZones,"+baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getAllDNS) == true {
		goddi.GetAllDNS(li.Conn, "DC="+*domain+",CN=MicrosoftDNS,DC=DomainDnsZones,"+baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getPolicy) == true {
		goddi.GetDomainAccountPolicy(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getdomainVersion) == true {
		goddi.GetDomainVersion(li.Conn, GetSchemaNamingContextEntry)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getSID) == true {
		goddi.GetDomainSID(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getExchangeInformation) == true {
		goddi.GetExchangeServerVersion(li.Conn, GetConfigurationContextEntry)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getmaq) == true{
		goddi.GetMAQ(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getNotusefulUser) == true {
		goddi.GetUsersLocked(li.Conn, baseDN)
		goddi.GetUsersDisabled(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getUsersNoExpire) == true {
		goddi.GetUsersNoExpire(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getDomainTrusts) == true {
		goddi.GetDomainTrusts(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getUsefulUserName) == true {
		goddi.Only_name_and_Useful_Users(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getAllUser) == true {
		goddi.GetUsers(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getComputersName) == true {
		goddi.Only_name_and_Useful_computers(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getComputers) == true {
		goddi.GetDomainComputers(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getHighlevelUser) == true {
		goddi.Only_admincout_Users(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getDomainGroup) == true {
		goddi.GetGroupsAll(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getCreatorSID) == true {
		goddi.CreatorSID(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getADCS) == true {
		goddi.GETADCS(li.Conn, "CN=Public Key Services,CN=Services,CN=Configuration,"+baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getDC) == true {
		goddi.GetDomainControllers(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*checkbackdoor) == true {
		goddi.SensitiveDelegateAccount(li.Conn, baseDN)
		goddi.GetMAQ(li.Conn, baseDN)
		goddi.AsReproast(li.Conn, baseDN)
		goddi.SIDHistory(li.Conn, baseDN)
		goddi.GetRBCD(li.Conn, baseDN)
		goddi.UnconstrainedDeligation(li.Conn, baseDN)
		goddi.ConstrainedDeligation(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getOU) == true {
		goddi.GetDomainOUs(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*checkLAPS) == true {
		goddi.GETIsHaveLAPS(li.Conn, "CN=Schema,CN=Configuration,"+baseDN)
		goddi.GetLAPS(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getMail) == true {
		goddi.GetMail(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getSPN) == true {
		goddi.GetSPN(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getGPO) == true {
		goddi.GetDomainGPOs(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*getDomainAdmins) == true {
		goddi.GetGroupMembers(li.Conn, baseDN, "Domain Admins")
		goddi.GetGroupMembers(li.Conn, baseDN, "Enterprise Admins")
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*dclocaladministrators) == true {
		goddi.GetGroupMembers(li.Conn, baseDN, "administrators")
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*BackupOperators) == true {
		goddi.GetGroupMembers(li.Conn, baseDN, "Backup Operators")
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	if (*Krbtgttime) == true{
		goddi.Krbtgttime(li.Conn, baseDN)
		stop := time.Since(start)
		cwd := goddi.GetCWD()
		fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
		os.Exit(1)
	}
	goddi.GetDomainVersion(li.Conn, GetSchemaNamingContextEntry)
	goddi.GetDomainSID(li.Conn, baseDN)
	goddi.GetMAQ(li.Conn, baseDN)
	goddi.GetDomainAccountPolicy(li.Conn, baseDN)
	goddi.GetDomainControllers(li.Conn, baseDN)
	goddi.GETADCS(li.Conn, "CN=Public Key Services,CN=Services,CN=Configuration,"+baseDN)
	goddi.GetExchangeServerVersion(li.Conn, GetConfigurationContextEntry)
	goddi.DC_and_Exchange_DNS(li.Conn, "DC="+*domain+",CN=MicrosoftDNS,DC=DomainDnsZones,"+baseDN)
	goddi.GetAllDNS(li.Conn, "DC="+*domain+",CN=MicrosoftDNS,DC=DomainDnsZones,"+baseDN)
	goddi.GetDomainTrusts(li.Conn, baseDN)
	goddi.GetSPN(li.Conn, baseDN)
	goddi.GetDomainGPOs(li.Conn, baseDN)
	goddi.GetGroupMembers(li.Conn, baseDN, "Domain Admins")
	goddi.GetGroupMembers(li.Conn, baseDN, "Enterprise Admins")
	goddi.GetGroupMembers(li.Conn, baseDN, "administrators")
	goddi.GetGroupMembers(li.Conn, baseDN, "Backup Operators")
	goddi.GetUsers(li.Conn, baseDN)
	goddi.GetMail(li.Conn, baseDN)
	goddi.Only_name_and_Useful_Users(li.Conn, baseDN)
	goddi.Only_admincout_Users(li.Conn, baseDN)
	goddi.GetUsersLocked(li.Conn, baseDN)
	goddi.GetUsersDisabled(li.Conn, baseDN)
	goddi.GetUsersNoExpire(li.Conn, baseDN)
	goddi.GetDomainComputers(li.Conn, baseDN)
	goddi.Only_name_and_Useful_computers(li.Conn, baseDN)
	goddi.GetGroupsAll(li.Conn, baseDN)
	goddi.GetDomainOUs(li.Conn, baseDN)
	goddi.GETIsHaveLAPS(li.Conn, "CN=Schema,CN=Configuration,"+baseDN)
	goddi.GetLAPS(li.Conn, baseDN)
	goddi.SensitiveDelegateAccount(li.Conn, baseDN)
	goddi.AsReproast(li.Conn, baseDN)
	goddi.SIDHistory(li.Conn, baseDN)
	goddi.CreatorSID(li.Conn, baseDN)
	goddi.GetRBCD(li.Conn, baseDN)
	goddi.UnconstrainedDeligation(li.Conn, baseDN)
	goddi.ConstrainedDeligation(li.Conn, baseDN)
	goddi.Krbtgttime(li.Conn, baseDN)
	//goddi.GetGPP(li.Conn, li.Domain, li.LdapServer, li.Usergpp, li.Pass)
	stop := time.Since(start)
	cwd := goddi.GetCWD()
	fmt.Printf("[i] CSVs written to 'csv' directory in %s\n[i] Execution took %s\n", cwd, stop)
}
