package ssh

import (
	_ "embed"
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

var (
	//go:embed data/debugserver.plist
	entitlementsData []byte
	//go:embed data/com.apple.system.logging.plist
	loggingPlistData []byte
	//go:embed data/com.apple.CrashReporter.plist
	symbolicationPlistData []byte
)

func hostKeyCallback(path string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		kh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600) //nolint:gomnd
		if err != nil {
			return fmt.Errorf("failed to open known_hosts: %w", err)
		}
		defer func() { _ = kh.Close() }()

		callback, err := knownhosts.New(kh.Name())
		if err != nil {
			return fmt.Errorf("failed to check known_hosts: %w", err)
		}

		if err := callback(hostname, remote, key); err != nil {
			var kerr *knownhosts.KeyError
			if errors.As(err, &kerr) {
				if len(kerr.Want) > 0 {
					return fmt.Errorf("possible man-in-the-middle attack: %w", err)
				}
				// if want is empty, it means the host was not in the known_hosts file, so lets add it there.
				fmt.Fprintln(kh, knownhosts.Line([]string{hostname}, key))
				return nil
			}
			return fmt.Errorf("failed to check known_hosts: %w", err)
		}
		return nil
	}
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
				ssh.Password(conf.Pass),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	} else {
		sshConfig = &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				ssh.Password(conf.Pass),
			},
			HostKeyCallback: hostKeyCallback(knownhostsPath),
		}
	}
	if signer != nil {
		sshConfig.Auth = append(sshConfig.Auth, ssh.PublicKeys(signer))
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
		return nil, fmt.Errorf("failed to create ssh session: %w", err)
	}
	defer session.Close()

	return session.Output("cat /dev/rdisk1 | dd bs=256 count=$((0x4000))")
}
