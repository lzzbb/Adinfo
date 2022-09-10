package goddi

import (
	"fmt"
	"github.com/bwmarrin/go-objectsid"
	"github.com/go-ldap/ldap/v3"
	"log"
	"strconv"
	"strings"
)

var Exchangename []string
var Controllername []string

func GetDomainVersion(conn *ldap.Conn, baseDN string) {
	attributes := []string{
		"objectVersion"}
	csv := [][]string{}
	csv = append(csv, attributes)
	filter := "(objectVersion=*)"
	sr := ldapSearch(baseDN, filter, attributes, conn)
	fmt.Printf("[i] DomainVersion found!\n")
	for _, entry := range sr.Entries {
		var getversion string
		switch versionget := entry.GetAttributeValue("objectVersion"); versionget {
		case "13":
			getversion = "Windows 2000 Server operating system"
		case "30":
			getversion = "Windows 2003 Server operating system"
		case "31":
			getversion = "Windows 2003 R2 Server operating system"
		case "44":
			getversion = "Windows 2008 Server operating system"
		case "47":
			getversion = "Windows 2008 R2 Server operating system"
		case "56":
			getversion = "Windows 2012 Server operating system"
		case "69":
			getversion = "Windows 2012 R2 Server operating system"
		case "87":
			getversion = "Windows 2016 Server operating system"
		case "88":
			getversion = "Windows 2019 Server operating system"
		default:
			getversion = "not fount!"
		}
		data := []string{
			getversion}
		csv = append(csv, data)
		fmt.Printf("                    [+] " + getversion + " \n")
	}
	writeCSV("DomainVersion", csv)
}

//func GETIsHaveAdcs(conn *ldap.Conn, baseDN string) {
//
//	attributes := []string{
//		"distinguishedName",
//		"cn",
//		"distinguishedName"}
//	filter := "(objectclass=certificationAuthority)"
//
//	csv := [][]string{}
//	csv = append(csv, attributes)
//
//	sr := ldapSearch(baseDN, filter, attributes, conn)
//
//	if len(sr.Entries) > 0 {
//		fmt.Printf("[i] ADCS has found!\n")
//	//}
//
//	for _, entry := range sr.Entries {
//		if (strings.Index(entry.GetAttributeValue("distinguishedName"), "Certification Authorities")) != -1 {
//			data := []string{
//				entry.GetAttributeValue("cn"),
//				entry.GetAttributeValue("distinguishedName")}
//			csv = append(csv, data)
//			fmt.Printf("                    [i] Root CA:  \n")
//			fmt.Printf("                    [+] " + entry.GetAttributeValue("distinguishedName") + " \n")
//		}
//	}
//	writeCSV("ADCS", csv)
//}
//}

func GETADCS(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"Root CA",
		"Enterprise CA",
		"cn",
		"distinguishedName",
		"dNSHostName",
		"whenCreated",
		"whenChanged"}
	filter  := "(objectclass=certificationAuthority)"
	filter1 := "(objectClass=pKIEnrollmentService)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)
	sr1 := ldapSearch(baseDN, filter1, attributes, conn)

	if len(sr.Entries) > 0 {
		fmt.Printf("[i] ADCS has found!\n")
		//}

		for _, entry := range sr.Entries {
			if (strings.Index(entry.GetAttributeValue("distinguishedName"), "Certification Authorities")) != -1 {
				data := []string{
					"√",
					"",
					entry.GetAttributeValue("cn"),
					entry.GetAttributeValue("distinguishedName"),
					"",
					entry.GetAttributeValue("whenCreated"),
					entry.GetAttributeValue("whenChanged")}
				csv = append(csv, data)
				fmt.Printf("                    [+] Root CA:" + "  ==>>>  " + entry.GetAttributeValue("cn") +"\n")

			}
		}

		for _, entry := range sr1.Entries {

				data := []string{
					"",
					"√",
					entry.GetAttributeValue("cn"),
					entry.GetAttributeValue("distinguishedName"),
					entry.GetAttributeValue("dNSHostName"),
					entry.GetAttributeValue("whenCreated"),
					entry.GetAttributeValue("whenChanged")}

				csv = append(csv, data)
				fmt.Printf("                    [+] Enterprise/Enrollment CA:" + "  ==>>>  " + entry.GetAttributeValue("cn") +"（computer FQDN: "+ entry.GetAttributeValue("dNSHostName") +"）"+"\n")

		}
		writeCSV("ADCS", csv)
	} else {
		fmt.Printf("[i] ADCS has not found!\n")
	}
}

func GetExchangeServerVersion(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"name",
		"serialNumber"}
	filter := "(objectCategory=msExchExchangeServer)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)
	fmt.Printf("[i] Domain Exchange Server: %d found\n", len(sr.Entries))
	if len(sr.Entries) > 0 {
		for _, entry := range sr.Entries {
			var getversion string
			Exchangename = append(Exchangename, entry.GetAttributeValue("name"))
			//fmt.Printf(Exchangename[0])
			versionget := entry.GetAttributeValue("serialNumber")
			account := entry.GetAttributeValue("name")
			if strings.Contains(versionget, "15.1") {
				getversion = "Exchange Server 2016"
			} else if strings.Contains(versionget, "15.0") {
				getversion = "Exchange Server 2013"
			} else if strings.Contains(versionget, "15.2") {
				getversion = "Exchange Server 2019"
			} else if strings.Contains(versionget, "14.") {
				getversion = "Exchange Server 2010"
			} else if strings.Contains(versionget, "8.") {
				getversion = "Exchange Server 2007"
			} else {
				getversion = "not fount!"
			}
			data := []string{
				account,
				getversion}
			csv = append(csv, data)
			fmt.Printf("                    [+] " + account + "$  ==>>>  " + getversion + " \n")
		}
		writeCSV("ExchangeInformation", csv)
	}
}

func GetUsers(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"sAMAccountType",
		"userPrincipalName",
		"displayName",
		"givenName",
		"description",
		"adminCount",
		"homeDirectory",
		"distinguishedName",
		"memberOf"}
	keywords := []string{
		"cred",
		"pass",
		"pw",
		"spring",
		"summer",
		"fall",
		"winter"}
	filter := "(&(objectCategory=person)(objectClass=user)(SamAccountName=*))"
	csv := [][]string{}
	csv = append(csv, attributes)
	warning := [][]string{}
	warning = append(warning, attributes)
	boolwarn := false

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Users: %d found\n", len(sr.Entries))

	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		samtype := entry.GetAttributeValue("sAMAccountType")
		upn := entry.GetAttributeValue("userPrincipalName")
		disname := entry.GetAttributeValue("displayName")
		given := entry.GetAttributeValue("givenName")
		desc := entry.GetAttributeValue("description")
		adm := entry.GetAttributeValue("adminCount")
		homedir := entry.GetAttributeValue("homeDirectory")
		distinguished := entry.GetAttributeValue("distinguishedName")
		mem := strings.Join(entry.GetAttributeValues("memberOf"), " ")
		data := []string{
			sam,
			samtype,
			upn,
			disname,
			given,
			desc,
			adm,
			homedir,
			distinguished,
			mem}

		csv = append(csv, data)

		for _, keyword := range keywords {
			if caseInsensitiveContains(desc, keyword) {
				fmt.Printf("\t[*] Warning: keyword '%s' found!\n", keyword)
				boolwarn = true
				warning = append(warning, data)
			}
		}
	}
	writeCSV("Users", csv)

	if boolwarn {
		writeCSV("POTENTIAL_SENSITIVE_DATA_FOUND", warning)
	}
}

func Only_name_and_Useful_Users(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName"}
	filter := "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!lockoutTime>=1))"
	csv := [][]string{}
	csv = append(csv, attributes)
	sr := ldapSearch(baseDN, filter, attributes, conn)
	fmt.Printf("[i] Only_name_and_Useful_Users: %d found\n", len(sr.Entries))

	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		data := []string{
			sam}

		csv = append(csv, data)
	}

	writeCSV("Users_OnlyName", csv)
}

func Only_admincout_Users(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName"}
	filter := "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=2)(!lockoutTime>=1)(admincount=1))"
	csv := [][]string{}
	csv = append(csv, attributes)
	sr := ldapSearch(baseDN, filter, attributes, conn)
	fmt.Printf("[i] Only_admincount=1_andUseful_Users: %d found\n", len(sr.Entries))

	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		data := []string{
			sam}

		csv = append(csv, data)
	}

	writeCSV("admincount_Users", csv)
}

func GetUsersLocked(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"sAMAccountType",
		"userPrincipalName",
		"displayName",
		"givenName",
		"description",
		"adminCount",
		"homeDirectory",
		"memberOf"}
	filter := "(&(sAMAccountType=805306368)(lockoutTime>=1))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Locked Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("sAMAccountType"),
			entry.GetAttributeValue("userPrincipalName"),
			entry.GetAttributeValue("displayName"),
			entry.GetAttributeValue("givenName"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("adminCount"),
			entry.GetAttributeValue("homeDirectory"),
			entry.GetAttributeValue("memberOf")}
		csv = append(csv, data)
	}
	writeCSV("Locked_Users", csv)
}

func GetUsersDisabled(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"sAMAccountType",
		"userPrincipalName",
		"displayName",
		"givenName",
		"description",
		"adminCount",
		"homeDirectory",
		"memberOf"}
	filter := "(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=2))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Disabled Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("sAMAccountType"),
			entry.GetAttributeValue("userPrincipalName"),
			entry.GetAttributeValue("displayName"),
			entry.GetAttributeValue("givenName"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("adminCount"),
			entry.GetAttributeValue("homeDirectory"),
			entry.GetAttributeValue("memberOf")}
		csv = append(csv, data)
	}
	writeCSV("Disabled_Users", csv)
}

func UnconstrainedDeligation(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"whenCreated",
		"whenChanged"}
	filter := "(&(userAccountControl:1.2.840.113556.1.4.803:=524288)(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] UnconstrainedDeligation Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged")}
		csv = append(csv, data)
		fmt.Printf("                    [+] "+entry.GetAttributeValue("sAMAccountName")+"\n")
	}
	writeCSV("UnconstrainedDeligation", csv)
}

func ConstrainedDeligation(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"whenCreated",
		"whenChanged",
		"msDS-AllowedToDelegateTo"}
	filter := "(userAccountControl:1.2.840.113556.1.4.803:=16777216)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] ConstrainedDeligation Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.GetAttributeValue("msDS-AllowedToDelegateTo")}
		csv = append(csv, data)
		fmt.Printf("                    [+] "+entry.GetAttributeValue("sAMAccountName")+"  ==>>>  "+entry.GetAttributeValue("msDS-AllowedToDelegateTo")+"\n")
	}
	writeCSV("ConstrainedDeligation", csv)
}

func GetUsersNoExpire(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"displayName",
		"description",
		"whenCreated",
		"whenChanged"}
	filter := "(&(samAccountType=805306368)(|(UserAccountControl:1.2.840.113556.1.4.803:=65536)(msDS-UserDontExpirePassword=TRUE)))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Users with passwords not set to expire: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("displayName"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged")}
		csv = append(csv, data)
	}
	writeCSV("NoExpirePasswords_Users", csv)
}

func Krbtgttime(conn *ldap.Conn, baseDN string) {

	attributes := []string{"pwdLastSet"}
	filter := "(&(objectCategory=person)(objectClass=user)(SamAccountName=krbtgt))"
	sr := ldapSearch(baseDN, filter, attributes, conn)
	for _, entry := range sr.Entries {
		pwdLastSet, _ := strconv.Atoi(entry.GetAttributeValue("pwdLastSet"))
		pwdLastSetString := ConvertLDAPTime(pwdLastSet).String()
		//fmt.Printf(string(pwdLastSetString))
		fmt.Printf("[i] Krbtgt password last set time: "+pwdLastSetString+"\n")
	}
}

func SensitiveDelegateAccount(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"mail",
		"whenCreated",
		"lastLogon",
		"memberOf"}
	filter := "(userAccountControl:1.2.840.113556.1.4.803:=1048576)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] SensitiveDelegate Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("mail"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("lastLogon"),
			entry.GetAttributeValue("memberOf")}
		csv = append(csv, data)
		fmt.Printf("                    [+] " + entry.GetAttributeValue("sAMAccountName") + " \n")
	}
	writeCSV("SensitiveDelegate_User", csv)
}

func GetMAQ(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"ms-DS-MachineAccountQuota"}
	filter := "(ms-DS-MachineAccountQuota=*)"
	csv := [][]string{}
	csv = append(csv, []string{"MAQ"})

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain MAQ found\n")
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("ms-DS-MachineAccountQuota")}
		csv = append(csv, data)
		fmt.Printf("                    [+] " + entry.GetAttributeValue("ms-DS-MachineAccountQuota") + " \n")
	}
	writeCSV("MAQ", csv)
}

func AsReproast(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"mail",
		"whenCreated",
		"lastLogon",
		"memberOf"}
	filter := "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] AsReporoast Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("mail"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("lastLogon"),
			entry.GetAttributeValue("memberOf")}
		csv = append(csv, data)
		fmt.Printf("                    [+] " + entry.GetAttributeValue("sAMAccountName") + " \n")
		//greencolor("                    [+] "+entry.GetAttributeValue("sAMAccountName")+ " \n")
	}
	writeCSV("AsReproast_User", csv)
}

func SIDHistory(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"mail",
		"sIDHistory",
		"whenCreated",
		"SidUser"}
	filter := "(sidhistory=*)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] SIDHistory Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		var sidString string = entry.GetAttributeValue("sIDHistory")
		var sidByte []byte = []byte(sidString)
		//fmt.Println(sidByte)
		sid := objectsid.Decode(sidByte)
		sidstr := sid.String()

		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("mail"),
			sidstr,
			entry.GetAttributeValue("whenCreated"),
			GetNameBySid(conn, baseDN, sidstr)}
		csv = append(csv, data)
		fmt.Printf("                    [+] " + entry.GetAttributeValue("sAMAccountName") + "  ==>>>  "+GetNameBySid(conn, baseDN, sidstr)+" \n")
	}

	writeCSV("SIDHistory_User", csv)
}

func GetNameBySid(conn *ldap.Conn, baseDN string, sidstrr string) string {
	filter := "(&(|(objectCategory=person)(objectCategory=Computer))(objectClass=user)(objectSid=*))"

	sidtouserName := ""
	attributes := []string{
		"sAMAccountName",
		"objectSid"}
	sr := ldapSearch(baseDN, filter, attributes, conn)
	for _, entry := range sr.Entries {
		var sidString string = entry.GetAttributeValue("objectSid")
		var sidByte []byte = []byte(sidString)
		//fmt.Println(sidByte)
		sid := objectsid.Decode(sidByte)
		sidstr := sid.String()

		sidmap := make(map[string]string)
		sidmap[sidstr] = entry.GetAttributeValue("sAMAccountName")
		//for key, value := range dict {
		//	fmt.Println(key, value)}
		if _, have := sidmap[sidstrr]; have {
			sidtouserName = sidmap[sidstrr]
		}
	}
	return sidtouserName
}


func GetFSMORoles(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"distinguishedname",
		"fSMORoleOwner"}
	filter := "(&(objectClass=*)(fSMORoleOwner=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] FSMO Roles: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.DN,
			entry.GetAttributeValue("fSMORoleOwner")}
		csv = append(csv, data)
	}
	writeCSV("Domain_FSMO_Roles", csv)
}

func GetDomainSite(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"name",
		"distinguishedname",
		"whenCreated",
		"whenChanged"}
	baseDN = "CN=Sites,CN=Configuration," + baseDN
	filter := "(&(objectCategory=site)(name=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Sites: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("Name"),
			entry.DN,
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged")}
		csv = append(csv, data)
	}
	writeCSV("Domain_Sites", csv)
}

func GetDomainSubnet(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"site",
		"name",
		"description",
		"whenCreated",
		"whenChanged",
		"distinguishedname"}
	baseDN = "CN=Subnets,CN=Sites,CN=Configuration," + baseDN
	filter := "(objectCategory=subnet)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Subnets: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("site"),
			entry.GetAttributeValue("name"),
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.DN}
		csv = append(csv, data)
	}
	writeCSV("Domain_Subnets", csv)
}

func GetDomainAccountPolicy(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"minPwdLength",
		"minPwdAge",
		"maxPwdAge",
		"pwdHistoryLength",
		"lockoutThreshold",
		"lockoutDuration"}
	filter := "(objectClass=domainDNS)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Account Policy found\n")

	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("minPwdLength"),
			convertPwdAge(entry.GetAttributeValue("minPwdAge")),
			convertPwdAge(entry.GetAttributeValue("maxPwdAge")),
			entry.GetAttributeValue("pwdHistoryLength"),
			entry.GetAttributeValue("lockoutThreshold"),
			convertLockout(entry.GetAttributeValue("lockoutDuration"))}
		csv = append(csv, data)
		fmt.Printf("                    [+] pwdHistory: "+entry.GetAttributeValue("pwdHistoryLength") +"\n")
		fmt.Printf("                    [+] minPwdLength: "+entry.GetAttributeValue("minPwdLength") +"\n")
		fmt.Printf("                    [+] minPwdAge: "+convertPwdAge(entry.GetAttributeValue("minPwdAge")) +"(day)\n")
		fmt.Printf("                    [+] maxPwdAge: "+convertPwdAge(entry.GetAttributeValue("maxPwdAge")) +"(day)\n")
		fmt.Printf("                    [+] lockoutThreshold: "+entry.GetAttributeValue("lockoutThreshold") +"\n")
		fmt.Printf("                    [+] lockoutDuration: "+convertLockout(entry.GetAttributeValue("lockoutDuration")) +"(min)\n")
	}
	writeCSV("Policy", csv)
}

func GetDomainOUs(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"ou",
		"dn",
		"ADsPath",
		"objectClass",
		"whenCreated",
		"whenChanged",
		"instanceType"}
	filter := "(&(objectCategory=organizationalUnit)(ou=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain OUs: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("ou"),
			entry.DN,
			baseDN,
			entry.GetAttributeValue("objectClass"),
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.GetAttributeValue("instanceType")}
		csv = append(csv, data)
	}
	writeCSV("Domain_OUs", csv)
}

func GetDomainGPOs(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"displayName",
		"dn",
		"gPCFileSysPath",
		"gPCUserExtensionNames",
		"gPCMachineExtensionNames"}
	filter := "(&(objectClass=groupPolicyContainer))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain GPOs: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("displayName"),
			entry.DN,
			entry.GetAttributeValue("gPCFileSysPath"),
			entry.GetAttributeValue("gPCUserExtensionNames"),
			entry.GetAttributeValue("gPCMachineExtensionNames")}
		csv = append(csv, data)
	}
	writeCSV("GPO", csv)
}

func GetGroupMembers(conn *ldap.Conn, baseDN string, group string) {

	attributes := []string{
		"memberOf",
		"sAMAccountName",
		"displayName",
		"distinguishedName"}
	csv := [][]string{}
	csv = append(csv, attributes)

	groupDN := getGroupDN(conn, baseDN, group)
	if len(groupDN) == 0 {
		writeCSV("Domain_Users_"+group, csv)
	}
	filter := "(&(objectCategory=user)(memberOf=" + groupDN + "))"

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] %s: %d users found\n", group, len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			group,
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("displayName"),
			entry.GetAttributeValue("distinguishedName")}
		csv = append(csv, data)
		fmt.Printf("                    [+]"+ entry.GetAttributeValue("sAMAccountName")+"\n")
	}

	writeCSV(group, csv)
}

func getGroupDN(conn *ldap.Conn, baseDN string, group string) string {

	attributes := []string{
		"memberOf",
		"sAMAccountName",
		"displayName"}
	filter := "(&(objectCategory=group)(samaccountname=" + group + "))"

	sr := ldapSearch(baseDN, filter, attributes, conn)

	if len(sr.Entries) != 0 {
		groupDN := sr.Entries[0].DN
		return groupDN
	}
	groupDN := ""
	return groupDN
}

func GetDomainComputers(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"dNSHostName",
		"operatingSystem",
		"operatingSystemVersion",
		"distinguishedName"}
	filter := "(&(objectCategory=Computer)(SamAccountName=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Computers: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("dNSHostName"),
			entry.GetAttributeValue("operatingSystem"),
			entry.GetAttributeValue("operatingSystemVersion"),
			entry.GetAttributeValue("distinguishedName")}
		csv = append(csv, data)
	}
	writeCSV("Computers", csv)
}

func Only_name_and_Useful_computers(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName"}
	filter := "(objectCategory=computer)"
	csv := [][]string{}
	csv = append(csv, attributes)
	sr := ldapSearch(baseDN, filter, attributes, conn)
	fmt.Printf("[i] Only_name_and_Useful_computers: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName")}
		csv = append(csv, data)
	}
	writeCSV("Computers_OnlyName", csv)
}

func GetSPN(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"servicePrincipalName",
		"dNSHostName",
		"memberOf"}
	filter := "(&(servicePrincipalName=*))"
	csv := [][]string{}
	csv = append(csv, attributes)
	count := 0

	sr := ldapSearch(baseDN, filter, attributes, conn)

	for _, entry := range sr.Entries {
		da := ""
		if caseInsensitiveContains(entry.GetAttributeValue("memberOf"), "Domain Admins") {
			da = "Domain Admins"
		}

		spns := entry.GetAttributeValues("servicePrincipalName")
		count += len(spns)
		for _, spn := range spns {
			data := []string{
				entry.GetAttributeValue("sAMAccountName"),
				spn,
				entry.GetAttributeValue("dNSHostName"),
				da}
			csv = append(csv, data)
		}
	}
	fmt.Printf("[i] SPN: %d found\n", count)
	writeCSV("SPN", csv)
}

func GetLAPS(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"dNSHostName",
		"ms-Mcs-AdmPwd",
		"ms-Mcs-AdmPwdExpirationTime"}
	filter := "(&(objectCategory=Computer))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	for _, entry := range sr.Entries {
		if len(entry.GetAttributeValue("ms-Mcs-AdmPwd")) > 0 {
			data := []string{
				entry.GetAttributeValue("dNSHostName"),
				entry.GetAttributeValue("ms-Mcs-AdmPwd"),
				entry.GetAttributeValue("ms-Mcs-AdmPwdExpirationTime")}
			csv = append(csv, data)
		}
	}
	fmt.Printf("[i] LAPS passwords: %d found\n", len(csv)-1)
	writeCSV("LAPS_Passwords", csv)
}

func GetDomainTrusts(conn *ldap.Conn, baseDN string) {
	attributes := []string{
		"sourcedomain",
		"trustPartner",
		"dn",
		"trustType",
		"trustDirection",
		"trustAttributes",
		"whenCreated",
		"whenChanged",
		"objectClass"}
	filter := "(objectClass=trustedDomain)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Trusts: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		var ttype, directory, attribute string
		switch trust := entry.GetAttributeValue("trustType"); trust {
		case "1":
			ttype = "Downlevel Trust (Windows NT domain external)"
		case "2":
			ttype = "Uplevel Trust (Active Directory domain - parent-child, root domain, shortcut, external, or forest)"
		case "3":
			ttype = "MIT (non-Windows Kerberos version 5 realm)"
		case "4":
			ttype = "DCE (Theoretical trust type - DCE refers to Open Group's Distributed Computing)"
		}
		switch dir := entry.GetAttributeValue("trustDirection"); dir {
		case "0":
			directory = "Disabled"
		case "1":
			directory = "Inbound"
		case "2":
			directory = "Outbound"
		case "3":
			directory = "Bidirectional"
		}
		switch attrib := entry.GetAttributeValue("trustAttributes"); attrib {
		case "1":
			attribute = "non_transitive"
		case "2":
			attribute = "uplevel_only"
		case "4":
			attribute = "quarantined_domain"
		case "8":
			attribute = "forest_transitive"
		case "10":
			attribute = "cross_organization"
		case "20":
			attribute = "within_forest"
		case "40":
			attribute = "treat_as_external"
		case "80":
			attribute = "trust_uses_rc4_encryption"
		case "100":
			attribute = "trust_uses_aes_keys"
		default:
			attribute = entry.GetAttributeValue("trustAttributes")
		}
		data := []string{
			baseDN,
			entry.GetAttributeValue("trustPartner"),
			entry.DN,
			ttype,
			directory,
			attribute,
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged"),
			entry.GetAttributeValue("objectClass")}
		csv = append(csv, data)
	}
	writeCSV("DomainTrusts", csv)
}

func GetGroupsAll(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"dn",
		"description",
		"adminCount",
		"member"}
	filter := "(&(objectClass=group)(samaccountname=*))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Groups: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.DN,
			entry.GetAttributeValue("description"),
			entry.GetAttributeValue("adminCount"),
			entry.GetAttributeValue("member")}
		csv = append(csv, data)
	}

	writeCSV("DomainGroups", csv)
}

func GETIsHaveLAPS(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"cn",
		"whenChanged"}
	filter := "(CN=ms-Mcs-AdmPwd)"
	csv := [][]string{}
	csv = append(csv, attributes)
	sr := ldapSearch(baseDN, filter, attributes, conn)

	if len(sr.Entries) > 0 {
		fmt.Printf("[i] LAPS has found\n")
	} else {
		fmt.Printf("[i] LAPS Not found\n")
	}
}

func GetMail(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"mail"}
	filter := "(&(objectCategory=person)(objectClass=user)(SamAccountName=*)(mail=*))"
	csv := [][]string{}
	csv = append(csv, attributes)
	sr := ldapSearch(baseDN, filter, attributes, conn)
	fmt.Printf("[i] User with Mail: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		sam := entry.GetAttributeValue("sAMAccountName")
		Mail := entry.GetAttributeValue("mail")
		data := []string{
			sam,
			Mail}
		csv = append(csv, data)

	}
	writeCSV("User_WithMail", csv)
}

func GetDomainControllers(conn *ldap.Conn, baseDN string) {
	attributes := []string{
		"sAMAccountName",
		"dNSHostName",
		"operatingSystem",
		"operatingSystemVersion"}
	filter := "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] Domain Controllers: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		Controllername = append(Controllername, entry.GetAttributeValue("sAMAccountName"))
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("dNSHostName"),
			entry.GetAttributeValue("operatingSystem"),
			entry.GetAttributeValue("operatingSystemVersion")}
		csv = append(csv, data)
		fmt.Printf("                    [+] "+entry.GetAttributeValue("sAMAccountName") + "  ==>>>   "+entry.GetAttributeValue("operatingSystem") +"  ["+entry.GetAttributeValue("operatingSystemVersion")+"]\n")
	}
	writeCSV("DomainControllers", csv)
}

func DC_and_Exchange_DNS(conn *ldap.Conn, baseDN string) {
	fmt.Printf("[i] DC and Exchange DNS: \n")

	attributes := []string{
		"name",
		"whenCreated",
		"dnsRecord",
		"dc",
		"exchange"}
	filter := "(objectClass=dnsNode)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)
	dnscount := 0

	for _, entry := range sr.Entries {
		var rawSidBytes [][]byte = entry.GetRawAttributeValues("dnsRecord")
		for _, sidByt := range rawSidBytes {
			ipa := ""
			if len(processDnsRecordAttribute(sidByt)) != 0 && entry.GetAttributeValue("name") != "DomainDnsZones" && entry.GetAttributeValue("name") != "ForestDnsZones" && entry.GetAttributeValue("name") != "@" {
				ipa = strconv.Itoa(int(processDnsRecordAttribute(sidByt)[0])) + "." + strconv.Itoa(int(processDnsRecordAttribute(sidByt)[1])) + "." + strconv.Itoa(int(processDnsRecordAttribute(sidByt)[2])) + "." + strconv.Itoa(int(processDnsRecordAttribute(sidByt)[3]))
				for _, value := range Controllername {
					if strings.EqualFold((entry.GetAttributeValue("name") + "$"), value) {
						data := []string{
							entry.GetAttributeValue("name"),
							entry.GetAttributeValue("whenCreated"),
							ipa,
							"√"}
						csv = append(csv, data)
						fmt.Printf("                    [+] "+entry.GetAttributeValue("name")+"$  ==>>>   "+ipa+"\n")
						dnscount++
					}
				}
				for _, value := range Exchangename {
					if strings.EqualFold((entry.GetAttributeValue("name")), value) {
						data := []string{
							entry.GetAttributeValue("name"),
							entry.GetAttributeValue("whenCreated"),
							ipa,
							"",
							"√"}
						csv = append(csv, data)
						fmt.Printf("                    [+] "+entry.GetAttributeValue("name")+"$  ==>>>   "+ipa+"\n")
						dnscount++
					}

				}
			}
		}
	}
	//fmt.Printf("                    " + "[+] Saved in DC_and_Exchange_DNS.csv \n")
	writeCSV("DC_and_Exchange_DNS", csv)
}

func GetAllDNS(conn *ldap.Conn, baseDN string) {
	fmt.Printf("[i] Domain All DNS:\n")
	attributes := []string{
		"name",
		"dnsRecord",
		"whenCreated"}
	filter := "(objectClass=dnsNode)"
	csv := [][]string{}
	csv = append(csv, attributes)
	sr := ldapSearch(baseDN, filter, attributes, conn)
	dnscount := 0

	for _, entry := range sr.Entries {
		var rawSidBytes [][]byte = entry.GetRawAttributeValues("dnsRecord")
		for _, sidByt := range rawSidBytes {
			ipa := ""
			if len(processDnsRecordAttribute(sidByt)) != 0 && entry.GetAttributeValue("name") != "DomainDnsZones" && entry.GetAttributeValue("name") != "ForestDnsZones" && entry.GetAttributeValue("name") != "@" {
				ipa = strconv.Itoa(int(processDnsRecordAttribute(sidByt)[0])) + "." + strconv.Itoa(int(processDnsRecordAttribute(sidByt)[1])) + "." + strconv.Itoa(int(processDnsRecordAttribute(sidByt)[2])) + "." + strconv.Itoa(int(processDnsRecordAttribute(sidByt)[3]))
				data := []string{
					entry.GetAttributeValue("name"),
					ipa,
					entry.GetAttributeValue("whenCreated")}
				csv = append(csv, data)
				dnscount++
			}
		}
	}
	fmt.Printf("                    [+]Domain Dns %d found,Saved in All_DNS.csv\n", dnscount)
	writeCSV("All_DNS", csv)
}

func GetRBCD(conn *ldap.Conn, baseDN string) {
	attributes := []string{
		"sAMAccountName",
		"msDS-AllowedToActOnBehalfOfOtherIdentity",
		"whenCreated",
		"whenChanged"}
	filter := "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] RBCD Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		var s = entry.GetAttributeValue("msDS-AllowedToActOnBehalfOfOtherIdentity")

		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			s,
			entry.GetAttributeValue("whenCreated"),
			entry.GetAttributeValue("whenChanged")}
		csv = append(csv, data)
		fmt.Printf("                    [+] "+entry.GetAttributeValue("sAMAccountName")+"\n")
	}
	writeCSV("RBCD", csv)
}

func CreatorSID(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"sAMAccountName",
		"mS-DS-CreatorSID",
		"CreatorUser"}
	filter := "(mS-DS-CreatorSID=*)"
	csv := [][]string{}
	csv = append(csv, attributes)

	sr := ldapSearch(baseDN, filter, attributes, conn)

	fmt.Printf("[i] CreatorSID Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		var sidString string = entry.GetAttributeValue("mS-DS-CreatorSID")
		var sidByte []byte = []byte(sidString)
		//fmt.Println(sidByte)
		sid := objectsid.Decode(sidByte)
		sidstr := sid.String()
		sidget := GetNameBySid(conn, baseDN, sidstr)
		data := []string{
			entry.GetAttributeValue("sAMAccountName"),
			sidstr,
			sidget}
		csv = append(csv, data)
		fmt.Printf("                    [+] "+entry.GetAttributeValue("sAMAccountName")+"  ==>>>  "+sidget+" \n")
	}

	writeCSV("CreatorSID_User", csv)
}

func GetDomainSID(conn *ldap.Conn, baseDN string) {

	attributes := []string{
		"objectSid"}
	filter := "(objectClass=domainDNS)"
	sr := ldapSearch(baseDN, filter, attributes, conn)
//	fmt.Printf("[i] CreatorSID Users: %d found\n", len(sr.Entries))
	for _, entry := range sr.Entries {
		var sidString string = entry.GetAttributeValue("objectSid")
		var sidByte []byte = []byte(sidString)
		//fmt.Println(sidByte)
		sid := objectsid.Decode(sidByte)
		sidstr := sid.String()
		fmt.Printf("[i] Domain SID: \n")
		fmt.Printf("                    [+] " + sidstr +"\n")
		}
	}

// Helper function for LDAP search
func ldapSearch(searchDN string, filter string, attributes []string, conn *ldap.Conn) *ldap.SearchResult {

	searchRequest := ldap.NewSearchRequest(
		searchDN,
		ldap.ScopeWholeSubtree, ldap.DerefAlways, 0, 0, false,
		filter,
		attributes,
		nil)

	sr, err := conn.SearchWithPaging(searchRequest, 200)
	if err != nil {
		log.Println(err)
	}
	return sr
}
