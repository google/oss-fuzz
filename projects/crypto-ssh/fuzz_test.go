package ssh_test

import (
	"testing"
	"golang.org/x/crypto/ssh"
)

func FuzzParsePublicKey(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Add([]byte{0, 0, 0, 7, 's', 's', 'h', '-', 'r', 's', 'a'})
	f.Add(make([]byte, 1000))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			key, _ := ssh.ParsePublicKey(data)
			if key != nil {
				_ = key.Type()
				ssh.MarshalAuthorizedKey(key)
			}
		}()
	})
}

func FuzzParseAuthorizedKey(f *testing.F) {
	f.Add("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@host\n")
	f.Add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@host\n")
	f.Add("")
	f.Add("\n")
	f.Add("# comment\n")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ssh.ParseAuthorizedKey([]byte(data))
		}()
	})
}

func FuzzParseKnownHosts(f *testing.F) {
	f.Add("localhost ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ==\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ssh.ParseKnownHosts([]byte(data))
		}()
	})
}

func FuzzParsePrivateKey(f *testing.F) {
	f.Add("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
	f.Add("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		if len(data) > 1<<16 { return }
		func() {
			defer func() { recover() }()
			ssh.ParsePrivateKey([]byte(data))
		}()
	})
}

func FuzzParsePrivateKeyWithPassphrase(f *testing.F) {
	f.Add("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n", "password")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, data, passphrase string) {
		if len(data) > 1<<16 || len(passphrase) > 1000 { return }
		func() {
			defer func() { recover() }()
			ssh.ParsePrivateKeyWithPassphrase([]byte(data), []byte(passphrase))
		}()
	})
}
