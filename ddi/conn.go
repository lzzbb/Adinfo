
package goddi

import (
	"crypto/tls"
	"fmt"
	"github.com/go-ldap/ldap/v3"
	"log"
)

// LdapInfo contains connection info
type LdapInfo struct {
	LdapServer  string
	LdapIP      string
	LdapPort    uint16
	LdapTLSPort uint16
	User        string
	Usergpp     string
	Hash		string
	Pass        string
	Domain      string
	Conn        *ldap.Conn
	Unsafe      bool
	StartTLS    bool
}

func dial(li *LdapInfo) {

	if li.Unsafe {

		fmt.Printf("[i] Try to connect '%s'\n", li.LdapServer)
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", li.LdapServer, li.LdapPort))
		if err != nil {
			log.Fatal(err)
		}

		//fmt.Printf("[c] connected successfully!\n")
		li.Conn = conn

	} else if li.StartTLS {

		fmt.Printf("[c] Begin PLAINTEXT LDAP connection to '%s' (%s)...\n", li.LdapServer, li.LdapIP)
		conn, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", li.LdapServer, li.LdapPort))
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("[c] PLAINTEXT LDAP connection to '%s' (%s) successful...\n[i] Upgrade to StartTLS connection...\n", li.LdapServer, li.LdapIP)

		err = conn.StartTLS(&tls.Config{ServerName: li.LdapServer})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("[c] Upgrade to StartTLS connection successful...\n")
		li.Conn = conn

	} else {

		fmt.Printf("[c] Begin LDAP TLS connection to '%s' (%s)...\n", li.LdapServer, li.LdapIP)
		config := &tls.Config{ServerName: li.LdapServer}
		conn, err := ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", li.LdapServer, li.LdapTLSPort), config)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Printf("[c] LDAP TLS connection to '%s' (%s) successful...\n", li.LdapServer, li.LdapIP)
		li.Conn = conn
	}
}

// Connect authenticated bind to ldap connection
func Connect(li *LdapInfo,ishash bool) {

	dial(li)
	if ishash {
		//err := li.Conn.Bind(li.User, li.Pass)
		fmt.Printf("[c] Auth Domain: "+li.Domain+"\n")
		fmt.Printf("[c] Auth user: "+li.User+"\n")
		fmt.Printf("[c] Auth hash: "+li.Hash+"\n")

		err := li.Conn.NTLMBindWithHash(li.Domain,li.User, li.Hash)
		//fmt.Printf(li.Domain+li.User+li.Ntlm+"\n")
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("[c] Auth Domain: "+li.Domain+"\n")
		fmt.Printf("[c] Auth user: "+li.User+"\n")
		fmt.Printf("[c] Auth Pass: "+li.Pass+"\n")
		err := li.Conn.Bind(li.User, li.Pass)
		if err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("[c] connected successfully,try to dump domain info\n")
}

