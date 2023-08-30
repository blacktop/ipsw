package ssh

import (
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/blacktop/ipsw/internal/utils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const defaultKeyPath = "$HOME/.ssh/id_rsa"

var (
	//go:embed data/debugserver.plist
	entitlementsData []byte
	//go:embed data/com.apple.system.logging.plist
	loggingPlistData []byte
	//go:embed data/com.apple.CrashReporter.plist
	symbolicationPlistData []byte
)

func keyString(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

func addHostKey(knownHosts string, remote net.Addr, pubKey ssh.PublicKey) error {
	f, err := os.OpenFile(knownHosts, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}
	defer f.Close()

	_, err = f.WriteString(knownhosts.Line([]string{knownhosts.Normalize(remote.String())}, pubKey))
	return err
}

// Config is the configuration for an SSH connection
type Config struct {
	Host     string
	Port     string
	User     string
	Pass     string
	Key      string
	Insecure bool
}

// SSH is an ssh object
type SSH struct {
	client *ssh.Client
	conf   *Config
}

// NewSSH creates a new SSH connection
func NewSSH(conf *Config) (*SSH, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}
	knownhostsPath := filepath.Join(home, ".ssh", "known_hosts")

	var signer ssh.Signer
	if len(conf.Key) > 0 {
		if conf.Key == defaultKeyPath {
			conf.Key = filepath.Join(home, ".ssh", "id_rsa")
		}
		key, err := os.ReadFile(conf.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %w", err)
		}
		signer, err = ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	var sshConfig *ssh.ClientConfig
	if conf.Insecure {
		sshConfig = &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
				ssh.Password("alpine"),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		// create known_hosts file if it doesn't exist
		if _, err := os.Stat(knownhostsPath); errors.Is(err, os.ErrNotExist) {
			f, err := os.OpenFile(knownhostsPath, os.O_CREATE, 0600)
			if err != nil {
				return nil, fmt.Errorf("failed to create known_hosts: %w", err)
			}
			f.Close()
		}

		hostKeyCallback, err := knownhosts.New(knownhostsPath)
		if err != nil {
			return nil, fmt.Errorf("failed to create ssh host key callback: %w", err)
		}

		sshConfig = &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
				ssh.Password("alpine"),
			},
			HostKeyCallback: hostKeyCallback,
		}
	}

	client, err := ssh.Dial("tcp", conf.Host+":"+conf.Port, sshConfig)
	if err != nil {
		log.Fatalf("failed to dial: %s", err)
	}

	return &SSH{
		client: client,
		conf:   conf,
	}, nil
}

// Close closes the SSH connection
func (s *SSH) Close() error {
	return s.client.Close()
}

// FileExists checks if a file exists on the remote device
func (s *SSH) FileExists(path string) bool {
	session, err := s.client.NewSession()
	if err != nil {
		log.Fatalf("failed to create session: %s", err)
	}
	defer session.Close()

	return session.Run(fmt.Sprintf("test -f %s", path)) == nil
}

// CopyToDevice copies a file to the remote device
func (s *SSH) CopyToDevice(src, dst string) error {
	session, err := s.client.NewSession()
	if err != nil {
		log.Fatalf("failed to create session: %s", err)
	}
	defer session.Close()

	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		count, err := io.Copy(w, f)
		if err != nil {
			log.Fatalf("failed to copy %s to device: %v", src, err)
		}
		if count == 0 {
			log.Fatalf("%d bytes copied to device", count)
		}
	}()

	if err := session.Start(fmt.Sprintf("cat > %s", dst)); err != nil {
		return fmt.Errorf("failed to copy %s to %s on device: %w", src, dst, err)
	}

	if err := session.Wait(); err != nil {
		return fmt.Errorf("failed to copy %s to device: %w", src, err)
	}

	return nil
}

// CopyFromDevice copies a file from the remote device
func (s *SSH) CopyFromDevice(src, dst string) error {
	session, err := s.client.NewSession()
	if err != nil {
		log.Fatalf("failed to create session: %s", err)
	}
	defer session.Close()

	f, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	go func() {
		w, _ := session.StdoutPipe()
		count, err := io.Copy(f, w)
		if err != nil {
			log.Fatalf("failed to copy %s from device: %v", src, err)
		}
		if count == 0 {
			log.Fatalf("%d bytes copied to device", count)
		}
	}()

	if err := session.Start(fmt.Sprintf("cat %s", src)); err != nil {
		return fmt.Errorf("failed to copy %s from device to %s: %w", src, dst, err)
	}

	if err := session.Wait(); err != nil {
		return fmt.Errorf("failed to copy %s from device: %w", src, err)
	}

	return nil
}

// RunCommand runs a command on the remote device
func (s *SSH) RunCommand(cmd string) error {
	session, err := s.client.NewSession()
	if err != nil {
		log.Fatalf("failed to create session: %s", err)
	}
	defer session.Close()

	err = session.Run(cmd)
	if err != nil {
		return fmt.Errorf("failed to run command: %w", err)
	}

	return nil
}

// RunCommandWithOutput runs a command on the remote device and returns the output
func (s *SSH) RunCommandWithOutput(cmd string) (string, error) {
	session, err := s.client.NewSession()
	if err != nil {
		log.Fatalf("failed to create session: %s", err)
	}
	defer session.Close()

	output, err := session.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to run command: %w", err)
	}

	return string(output), nil
}

// ResignDebugserver resigns debugserver with more powerful entitlements
func ResignDebugserver(dspath string) error {
	entitlements, err := os.CreateTemp("", "entitlements.plist")
	if err != nil {
		return fmt.Errorf("failed to create tmp entitlements file: %w", err)
	}
	defer os.Remove(entitlements.Name()) // clean up

	if _, err := entitlements.Write(entitlementsData); err != nil {
		return fmt.Errorf("failed to write entitlements.plist data to tmp file: %w", err)
	}
	if err := entitlements.Close(); err != nil {
		return fmt.Errorf("failed to close tmp entitlements.plist file: %w", err)
	}

	if err := utils.CodeSignWithEntitlements(dspath, entitlements.Name(), "-"); err != nil {
		return fmt.Errorf("failed to codesign debugserver with entitlements: %w", err)
	}

	return nil
}

// EnablePrivateLogData enables private data in logs
// CREDIT - https://github.com/EthanArbuckle/unredact-private-os_logs
func (s *SSH) EnablePrivateLogData() error {
	logging, err := os.CreateTemp("", "com.apple.system.logging.plist")
	if err != nil {
		return fmt.Errorf("failed to create tmp entitlements file: %w", err)
	}
	defer os.Remove(logging.Name()) // clean up

	if _, err := logging.Write(loggingPlistData); err != nil {
		return fmt.Errorf("failed to write com.apple.system.logging.plist data to tmp file: %w", err)
	}
	if err := logging.Close(); err != nil {
		return fmt.Errorf("failed to close tmp com.apple.system.logging.plist file: %w", err)
	}

	return s.CopyToDevice(logging.Name(), "/Library/Preferences/Logging/com.apple.system.logging.plist")
}

// EnableSymbolication enables symbolication of mobile crash logs
// CREDIT -	https://github.com/dlevi309/ios-scripts
func (s *SSH) EnableSymbolication() error {
	crashReporter, err := os.CreateTemp("", "com.apple.CrashReporter.plist")
	if err != nil {
		return fmt.Errorf("failed to create tmp 'com.apple.CrashReporter.plist' file: %w", err)
	}
	defer os.Remove(crashReporter.Name()) // clean up

	if _, err := crashReporter.Write(symbolicationPlistData); err != nil {
		return fmt.Errorf("failed to write 'com.apple.CrashReporter.plist' data to tmp file: %w", err)
	}
	if err := crashReporter.Close(); err != nil {
		return fmt.Errorf("failed to close tmp 'com.apple.CrashReporter.plist' file: %w", err)
	}
	return s.CopyToDevice(crashReporter.Name(), "/var/root/Library/Preferences/com.apple.CrashReporter.plist")
}

func (s *SSH) GetShshBlobs() ([]byte, error) {
	session, err := s.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %s", err)
	}
	defer session.Close()

	r, err := session.StdoutPipe()
	if err != nil {
		return nil, err
	}

	if err := session.Start("cat /dev/rdisk1 | dd bs=256 count=$((0x4000))"); err != nil {
		return nil, err
	}

	var out []byte
	if _, err := r.Read(out); err != nil {
		return nil, err
	}

	return out, session.Wait()
}
