package appstore

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/blacktop/go-plist"
	"github.com/blacktop/ipsw/internal/certs"
	"github.com/blacktop/ipsw/internal/utils"
	"github.com/fullsailor/pkcs7"
	// "software.sslmate.com/src/go-pkcs12"
)

const rsaKeySize = 2048 // Standard key size

type ProvisionSigningFilesConfig struct {
	CertType string
	BundleID string
	CSR      bool
	Email    string
	Country  string
	Install  bool
	Output   string
}

// ProvisionSigningFiles retrieves or creates, then installs, the necessary
// certificate and provisioning profile for iOS development signing.
func (as *AppStore) ProvisionSigningFiles(conf *ProvisionSigningFilesConfig) error {
	if as.token == "" {
		log.Info("Authenticating with App Store Connect API...")
		if err := as.createToken(defaultJWTLife); err != nil {
			return fmt.Errorf("failed to create API token: %w", err)
		}
	}

	as.conf = conf

	// Determine required certificate type and profile type based on input
	var requiredCertType CertificateType
	var requiredProfileType ProfileType
	var typeLabel string // For logging and filenames

	switch strings.ToLower(conf.CertType) {
	case "development":
		requiredCertType = CT_DEVELOPMENT
		requiredProfileType = IOS_APP_DEVELOPMENT
		typeLabel = "Development"
	case "adhoc":
		requiredCertType = CT_DISTRIBUTION // AdHoc uses Distribution cert
		requiredProfileType = IOS_APP_ADHOC
		typeLabel = "AdHoc"
	case "distribution":
		requiredCertType = CT_DISTRIBUTION // App Store uses Distribution cert
		requiredProfileType = IOS_APP_STORE
		typeLabel = "AppStore"
	default:
		return fmt.Errorf("invalid certificate type specified: %s", conf.CertType)
	}

	log.Infof("Checking for %s Certificate...", typeLabel)
	certResource, generatedKeyPath, err := as.ensureCertificate(requiredCertType, typeLabel, conf.Output, conf.CSR)
	if err != nil {
		return fmt.Errorf("failed to ensure %s certificate: %w", typeLabel, err)
	}

	certFilename := fmt.Sprintf("%s_%s.cer", strings.ToLower(typeLabel), certResource.ID)
	certPath := filepath.Join(conf.Output, certFilename)
	if err = os.WriteFile(certPath, certResource.Attributes.CertificateContent, 0644); err != nil {
		// Attempt cleanup if key was generated
		if generatedKeyPath != "" {
			os.Remove(generatedKeyPath)
		}
		return fmt.Errorf("failed saving %s certificate file %s: %w", typeLabel, certPath, err)
	}
	log.Infof("%s Certificate ID: %s (Saved to %s)", typeLabel, certResource.ID, certPath)
	if generatedKeyPath != "" {
		log.Warnf("Generated Private Key saved to: %s", generatedKeyPath)
		utils.Indent(log.Warn, 2)("‼️ Private key file saved locally. Ensure it is secured or deleted after import.")
		// TODO: Export certificate and key as a password protected .p12 file
		// // Export certificate and key as a .p12 file
		// p12Filename := fmt.Sprintf("%s_%s.p12", strings.ToLower(typeLabel), certResource.ID)
		// p12Path := filepath.Join(conf.Output, p12Filename)
		// if err := exportToP12(certPath, generatedKeyPath, p12Path, "ipsw"); err != nil {
		// 	log.Warnf("Failed to export certificate and key to P12: %v", err)
		// } else {
		// 	log.Infof("Certificate and key exported to %s", p12Path)
		// }
	}

	log.Infof("Checking for %s Provisioning Profile...", typeLabel)
	profileResource, err := as.ensureProvisioningProfile(conf.BundleID, certResource.ID, requiredProfileType, typeLabel)
	if err != nil {
		// Attempt cleanup
		os.Remove(certPath)
		if generatedKeyPath != "" {
			os.Remove(generatedKeyPath)
		}
		return fmt.Errorf("failed to ensure %s provisioning profile: %w", typeLabel, err)
	}

	profileFilename := fmt.Sprintf("ipsw_%s_%s.mobileprovision", typeLabel, conf.BundleID)
	profilePath := filepath.Join(conf.Output, profileFilename)
	if err = os.WriteFile(profilePath, profileResource.Attributes.ProfileContent, 0644); err != nil {
		// Attempt cleanup
		os.Remove(certPath)
		if generatedKeyPath != "" {
			os.Remove(generatedKeyPath)
		}
		return fmt.Errorf("failed saving %s provisioning profile file %s: %w", typeLabel, profilePath, err)
	}
	log.Infof("%s Provisioning Profile ID: %s (Saved to %s)", typeLabel, profileResource.ID, profilePath)

	if conf.Install {
		log.Info("Installing assets locally...")
		err = InstallCertificateAndKey(certPath, generatedKeyPath) // Pass generated key path
		if err != nil {
			log.Warnf("Failed to install certificate/key into Keychain: %v", err)
			utils.Indent(log.Warn, 2)("You may need to install them manually")
			// Continue to profile installation even if cert install fails
		} else {
			log.Infof("Certificate %s and associated key installed into login keychain.", certFilename)
			if generatedKeyPath != "" {
				log.Infof("Deleting temporary private key file: %s", generatedKeyPath)
				os.Remove(generatedKeyPath) // Best effort
			}
		}
		log.Info("Installing Provisioning Profile...")
		if installedName, err := InstallProvisioningProfile(profilePath); err != nil {
			log.Warnf("Failed to install provisioning profile: %v", err)
			utils.Indent(log.Warn, 2)("You may need to install it manually by copying it to ~/Library/MobileDevice/Provisioning Profiles/ (using the profile's UUID as filename.mobileprovision)")
		} else {
			log.Infof("Provisioning Profile installed: %s", installedName)
		}
	}

	return nil
}

// ensureCertificate finds a valid certificate of the required type or creates a new one.
// Takes the required CertificateType constant and a label for logging/filenames.
func (as *AppStore) ensureCertificate(requiredCertType CertificateType, typeLabel, outputDir string, newCSR bool) (certRes *Certificate, keyPath string, err error) {
	if !newCSR {
		log.Debugf("Fetching all certificates...")
		allCerts, err := as.GetCertificates()
		if err != nil {
			return nil, "", fmt.Errorf("getting certificates: %w", err)
		}
		log.Debugf("Retrieved %d certificates. Filtering for valid %s certs...", len(allCerts), typeLabel)
		for _, cert := range allCerts {
			// Check if it's the required type
			if cert.Attributes.CertificateType != requiredCertType {
				continue // Skip wrong types
			}
			// Check if the certificate is valid (not expired and more than 30 days left)
			if time.Time(cert.Attributes.ExpirationDate).After(time.Now().Add(30 * 24 * time.Hour)) {
				log.WithFields(log.Fields{
					"id":     cert.ID,
					"name":   cert.Attributes.Name,
					"serial": cert.Attributes.SerialNumber,
				}).Infof("Found valid existing %s", typeLabel)
				return &cert, "", nil // No key generated
			}
			log.WithFields(log.Fields{
				"id":      cert.ID,
				"name":    cert.Attributes.Name,
				"expires": cert.Attributes.ExpirationDate.Format(time.RFC1123),
			}).Debugf("Found %s expired/expiring soon", typeLabel)
		}
		log.Infof("No valid existing %s certificate found. Creating a new one...", typeLabel)
	} else {
		log.Infof("Forcing creation of a new %s certificate...", typeLabel)
	}

	log.Debug("Generating RSA private key...")
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
	if err != nil {
		return nil, "", fmt.Errorf("generating private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	// Save private key locally using typeLabel in filename
	keyFilename := fmt.Sprintf("%s_private_key.pem", strings.ToLower(typeLabel))
	generatedKeyPath := filepath.Join(outputDir, keyFilename)
	if err := os.WriteFile(generatedKeyPath, privateKeyPEM, 0600); err != nil {
		return nil, "", fmt.Errorf("saving generated private key: %w", err)
	}
	log.Debugf("Private key generated and saved to %s (Permissions 0600)", generatedKeyPath)

	log.Debug("Generating Certificate Signing Request (CSR)...")
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: certs.OIDEmailAddress, Value: as.conf.Email},
			},
			CommonName: fmt.Sprintf("%s Dev Key %s", typeLabel, time.Now().Format("20060102150405")),
			Country:    []string{as.conf.Country},
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
		// EmailAddresses:     []string{as.conf.Email},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		os.Remove(generatedKeyPath) // Cleanup generated key
		return nil, "", fmt.Errorf("creating CSR: %w", err)
	}
	// csrPath := filepath.Join(outputDir, fmt.Sprintf("%s.certSigningRequest", strings.ToLower(typeLabel)))
	// if err := os.WriteFile(csrPath, csrBytes, 0600); err != nil {
	// 	return nil, "", fmt.Errorf("saving CSR: %w", err)
	// }
	// log.Infof("Certificate Signing Request (CSR) saved to %s", csrPath)
	// NOTE: openssl req -in development.certSigningRequest -noout -text
	log.Info("Submitting CSR to App Store Connect...")
	createdCert, err := as.CreateCertificate(
		string(requiredCertType), // Pass the required type as string
		base64.StdEncoding.EncodeToString(csrBytes),
	)
	if err != nil {
		os.Remove(generatedKeyPath) // Cleanup generated key
		return nil, "", fmt.Errorf("creating %s certificate via API: %w", typeLabel, err)
	}

	log.WithField("id", createdCert.ID).Infof("Successfully created new %s certificate", typeLabel)
	utils.Indent(log.Info, 2)(
		fmt.Sprintf("New Certificate Details - Name: %s, Serial: %s, Expires: %s",
			createdCert.Attributes.Name,
			createdCert.Attributes.SerialNumber,
			createdCert.Attributes.ExpirationDate.Format(time.RFC1123),
		))

	return createdCert, generatedKeyPath, nil
}

// ensureProvisioningProfile finds or creates a provisioning profile of the specified type.
// Takes the required ProfileType constant and a label for logging/filenames.
func (as *AppStore) ensureProvisioningProfile(bundleIDIdentifier string, certID string, requiredProfileType ProfileType, typeLabel string) (prof *Profile, err error) {

	log.Debugf("Looking up Bundle ID resource for identifier: %s", bundleIDIdentifier)
	bundle, err := as.GetBundleID(bundleIDIdentifier)
	if err != nil {
		return nil, fmt.Errorf("finding bundle ID '%s': %w", bundleIDIdentifier, err)
	}

	log.Debug("Listing all devices...")
	allDevices, err := as.GetDevices()
	if err != nil {
		return nil, fmt.Errorf("listing devices: %w", err)
	}

	deviceIDs := make([]string, 0)
	enabledDeviceCount := 0
	// Only include devices for Development and AdHoc profiles
	// AppStore profiles don't include specific devices
	if requiredProfileType == IOS_APP_DEVELOPMENT || requiredProfileType == IOS_APP_ADHOC {
		for _, dev := range allDevices {
			if dev.Attributes.Status == "ENABLED" { // Filter for enabled status
				deviceIDs = append(deviceIDs, dev.ID)
				enabledDeviceCount++
			}
		}
		if enabledDeviceCount == 0 {
			log.Warnf("No enabled devices found in the account. %s profile might not work or will be created without devices.", typeLabel)
		} else {
			log.Infof("Found %d enabled devices to include in %s profile.", enabledDeviceCount, typeLabel)
		}
	} else {
		log.Debugf("%s profiles do not include specific devices.", typeLabel)
	}

	profileName := fmt.Sprintf("ipsw %s %s", typeLabel, bundleIDIdentifier)
	log.Infof("Attempting to find existing profile named: %s", profileName)

	allProfiles, err := as.GetProfiles()
	if err != nil {
		log.Warnf("Failed to list existing profiles, will attempt creation: %v", err)
	} else {
		log.Debugf("Retrieved %d profiles. Filtering for suitable %s profile...", len(allProfiles), typeLabel)
		for _, p := range allProfiles {
			// Check name, type, and state
			if p.Attributes.Name == profileName &&
				p.Attributes.ProfileType == requiredProfileType && // Check against the required type
				p.Attributes.ProfileState == "ACTIVE" {
				// Check if it contains the required certificate
				containsCert := false
				certs, err := as.GetProfileCerts(p.ID)
				if err != nil {
					log.Warnf("Failed to list certificates for profile %s: %v", p.ID, err)
					continue // Skip this profile
				}
				for _, c := range certs {
					if c.ID == certID {
						containsCert = true
						break
					}
				}
				// Check if it's for the correct bundle ID
				containsBundleID := false
				pb, err := as.GetProfileBundleID(p.ID)
				if err != nil {
					log.Warnf("Failed to list bundle IDs for profile %s: %v", p.ID, err)
					continue // Skip this profile
				}
				if pb.ID == bundle.ID {
					containsBundleID = true
				}
				// Check device count consistency (optional but good)
				// AdHoc/Dev profiles should ideally have the devices we found earlier
				// AppStore profiles should have zero devices associated
				devicesMatch := true
				if requiredProfileType == IOS_APP_DEVELOPMENT || requiredProfileType == IOS_APP_ADHOC {
					profileDevices, err := as.GetProfileDevices(p.ID)
					if err != nil {
						log.Warnf("Could not verify devices for existing profile %s: %v", p.ID, err)
						// Decide if this is critical - maybe continue if cert/bundle match
					} else if len(profileDevices) != len(deviceIDs) {
						log.Debugf("Existing profile %s has %d devices, but %d enabled devices found now. May need regeneration.", p.ID, len(profileDevices), len(deviceIDs))
						// Could force regeneration here if needed: continue
						devicesMatch = false // Mark as mismatch for now, maybe regenerate later
					}
				} else { // AppStore profile
					profileDevices, _ := as.GetProfileDevices(p.ID) // Check anyway
					if len(profileDevices) > 0 {
						log.Warnf("Existing AppStore profile %s unexpectedly contains devices.", p.ID)
						devicesMatch = false // AppStore profiles shouldn't have devices
					}
				}
				// If all conditions match, use this profile
				if containsCert && containsBundleID && devicesMatch { // Added devicesMatch check
					log.Infof("Found suitable existing %s profile: ID %s, State: %s", typeLabel, p.ID, p.Attributes.ProfileState)
					return &p, nil
				} else {
					log.Debugf("Profile %s matched name/type/state but failed checks: cert=%t, bundleID=%t, devices=%t", p.ID, containsCert, containsBundleID, devicesMatch)
				}
			}
		}
		log.Infof("No suitable active profile found named '%s'. Proceeding to create.", profileName)
	}

	log.Infof("Attempting to create a new %s Provisioning Profile...", typeLabel)
	// Use the requiredProfileType constant
	createResp, err := as.CreateProfile(
		profileName,
		string(requiredProfileType), // Pass the required type as string
		bundle.ID,
		[]string{certID},
		deviceIDs, // Pass the filtered list (empty for AppStore)
		false,     // offline=false
	)
	if err != nil {
		return nil, fmt.Errorf("creating %s provisioning profile: %w", typeLabel, err)
	}

	log.WithFields(log.Fields{
		"id":   createResp.Data.ID,
		"name": profileName,
	}).Infof("Successfully created %s Provisioning Profile", typeLabel)

	return &createResp.Data, nil
}

// InstallCertificateAndKey imports the certificate and optionally its private key into the login keychain.
func InstallCertificateAndKey(certPath string, keyPath string) error {
	// If keyPath is provided, install the private key
	if keyPath != "" {
		if err := installPrivateKey(keyPath); err != nil {
			return fmt.Errorf("installing private key: %w", err)
		}
	} else {
		log.Info("No private key path provided, skipping key import (assuming key already exists in keychain).")
	}

	// Install the certificate
	if err := installCertificate(certPath); err != nil {
		return fmt.Errorf("installing certificate: %w", err)
	}

	// Verify installation (same as before)
	return VerifyCertificateInstallation(certPath)
}

// installPrivateKey imports a private key into the login keychain.
func installPrivateKey(keyPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting user home directory: %w", err)
	}

	// Determine correct keychain path (.keychain-db suffix is newer)
	keychainPath := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	if _, err := os.Stat(keychainPath); os.IsNotExist(err) {
		keychainPath = filepath.Join(home, "Library", "Keychains", "login.keychain")
		if _, err := os.Stat(keychainPath); os.IsNotExist(err) {
			return fmt.Errorf("cannot find login keychain at default locations")
		}
	}

	log.Infof("Importing private key %s into keychain %s", keyPath, keychainPath)
	// -P "" assumes empty passphrase. If key is encrypted, this will fail.
	// -T /usr/bin/codesign : Allow codesign to use this key without UI prompt.
	cmdKey := exec.Command("security", "import", keyPath, "-k", keychainPath, "-P", "", "-T", "/usr/bin/codesign")
	outputKey, errKey := cmdKey.CombinedOutput()
	if errKey != nil {
		// Retry without -P "" (for non-encrypted keys that might reject empty passphrase)
		log.Debugf("Initial key import failed, retrying without -P '': %v", errKey)
		cmdKeyRetry := exec.Command("security", "import", keyPath, "-k", keychainPath, "-T", "/usr/bin/codesign")
		outputKeyRetry, errKeyRetry := cmdKeyRetry.CombinedOutput()
		if errKeyRetry != nil {
			return fmt.Errorf("security import command failed for private key: %w\nAttempt 1 Output: %s\nAttempt 2 Output: %s", errKeyRetry, string(outputKey), string(outputKeyRetry))
		}
		log.Debugf("Security import (retry) output for key: %s", string(outputKeyRetry))
	} else {
		log.Debugf("Security import output for key: %s", string(outputKey))
	}
	log.Info("Private key imported.")
	return nil
}

// installCertificate imports a certificate into the login keychain.
func installCertificate(certPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting user home directory: %w", err)
	}

	// Determine correct keychain path (.keychain-db suffix is newer)
	keychainPath := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	if _, err := os.Stat(keychainPath); os.IsNotExist(err) {
		keychainPath = filepath.Join(home, "Library", "Keychains", "login.keychain")
		if _, err := os.Stat(keychainPath); os.IsNotExist(err) {
			return fmt.Errorf("cannot find login keychain at default locations")
		}
	}

	// Import Certificate
	log.Infof("Importing certificate %s into keychain %s", certPath, keychainPath)
	cmdCert := exec.Command("security", "import", certPath, "-k", keychainPath)
	outputCert, errCert := cmdCert.CombinedOutput()
	if errCert != nil {
		return fmt.Errorf("security import command failed for certificate: %w\nOutput: %s", errCert, string(outputCert))
	}
	log.Debugf("Security import output for certificate: %s", string(outputCert))
	log.Info("Certificate imported.")
	return nil
}

// VerifyCertificateInstallation verifies that a certificate was properly installed.
func VerifyCertificateInstallation(certPath string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("getting user home directory: %w", err)
	}

	// Determine correct keychain path (.keychain-db suffix is newer)
	keychainPath := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
	if _, err := os.Stat(keychainPath); os.IsNotExist(err) {
		keychainPath = filepath.Join(home, "Library", "Keychains", "login.keychain")
		if _, err := os.Stat(keychainPath); os.IsNotExist(err) {
			return fmt.Errorf("cannot find login keychain at default locations")
		}
	}

	// Verify Installation (Find Identity)
	// Need to parse the cert to get the Common Name for verification
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		log.Warnf("Cannot read certificate file %s for verification: %v", certPath, err)
		return nil // Don't fail the whole process, just warn
	}
	// Handle PEM encoding if necessary (App Store Connect usually provides DER)
	block, _ := pem.Decode(certBytes)
	var certRaw []byte
	if block != nil {
		certRaw = block.Bytes
	} else {
		certRaw = certBytes // Assume DER
	}

	parsedCert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		log.Warnf("Cannot parse certificate %s for verification: %v", certPath, err)
		return nil // Don't fail, just warn
	}
	commonName := parsedCert.Subject.CommonName
	if commonName == "" {
		log.Warnf("Certificate %s has no Common Name, cannot verify identity precisely.", certPath)
		return nil
	}

	log.Infof("Verifying identity '%s' in keychain %s...", commonName, keychainPath)
	// -v : valid identities only, -p codesigning : for code signing usage
	cmdVerify := exec.Command("security", "find-identity", "-v", "-p", "codesigning", keychainPath)
	verifyOutput, errVerify := cmdVerify.CombinedOutput()

	found := false
	if errVerify == nil {
		for line := range strings.SplitSeq(string(verifyOutput), "\n") {
			// Match common name within quotes: "iPhone Developer: Your Name (TEAMID)"
			if strings.Contains(line, fmt.Sprintf(`"%s"`, commonName)) || strings.Contains(line, commonName) { // Be a bit lenient
				log.Infof("Verification successful: Found identity matching '%s'", commonName)
				log.Debugf("Full matching line: %s", strings.TrimSpace(line))
				found = true
				break
			}
		}
	}

	if !found {
		// This is a significant warning, but maybe not a fatal error depending on user workflow
		log.Warnf("Could not verify identity '%s' was successfully installed for code signing in %s.", commonName, keychainPath)
		if errVerify != nil {
			log.Debugf("Verification command 'security find-identity' failed: %v", errVerify)
		}
		return fmt.Errorf("failed to verify certificate and key combination in keychain for CN '%s'", commonName)
	}

	return nil
}

// InstallProvisioningProfile copies the profile to the standard location.
func InstallProvisioningProfile(profilePath string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("getting user home directory: %w", err)
	}

	profileDir := filepath.Join(home, "Library", "MobileDevice", "Provisioning Profiles")
	if err = os.MkdirAll(profileDir, 0755); err != nil {
		return "", fmt.Errorf("creating profiles directory %s: %w", profileDir, err)
	}

	profileData, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("reading profile %s: %w", profilePath, err)
	}

	// Extract UUID from the profile
	destName := filepath.Base(profilePath)
	uuid, err := extractProfileUUID(profileData)
	if err != nil {
		log.Warnf("Could not extract UUID from profile: %v", err)
		log.Warnf("Using original filename instead: %s", destName)
	} else {
		// Default to original name if parsing fails
		destName = uuid + ".mobileprovision"
		log.Debugf("Extracted UUID from profile: %s", uuid)
	}

	destPath := filepath.Join(profileDir, destName)

	log.Infof("Copying profile %s to %s", profilePath, destPath)
	if err = os.WriteFile(destPath, profileData, 0644); err != nil {
		return "", fmt.Errorf("writing profile to %s: %w", destPath, err)
	}

	if err = os.Chmod(destPath, 0644); err != nil {
		log.Warnf("Failed to set permissions on %s: %v", destPath, err)
	}

	return destPath, nil
}

// extractProfileUUID parses a provisioning profile to extract its UUID.
// .mobileprovision files are in PKCS#7 (CMS) format with an embedded plist
func extractProfileUUID(profileData []byte) (string, error) {
	p7, err := pkcs7.Parse(profileData)
	if err != nil {
		return "", fmt.Errorf("parse PKCS#7 data: %w", err)
	}

	if len(p7.Content) == 0 {
		return "", fmt.Errorf("no content found in PKCS#7 data")
	}

	type minimalProfile struct {
		UUID string `plist:"UUID,omitempty"`
	}

	var profile minimalProfile
	if _, err := plist.Unmarshal(p7.Content, &profile); err != nil {
		return "", fmt.Errorf("unmarshal provisioning profile plist: %w", err)
	}

	if profile.UUID == "" {
		return "", fmt.Errorf("no UUID found in provisioning profile")
	}

	return profile.UUID, nil
}

// exportToP12 combines a certificate and private key into a PKCS#12 (.p12) file
// func exportToP12(certPath, keyPath, p12Path, password string) error {
// 	certData, err := os.ReadFile(certPath)
// 	if err != nil {
// 		return fmt.Errorf("reading certificate file: %w", err)
// 	}

// 	// Parse certificate - handle both PEM and DER formats
// 	var cert *x509.Certificate
// 	block, _ := pem.Decode(certData)
// 	if block != nil && block.Type == "CERTIFICATE" {
// 		// PEM format
// 		cert, err = x509.ParseCertificate(block.Bytes)
// 		if err != nil {
// 			return fmt.Errorf("parsing PEM certificate: %w", err)
// 		}
// 	} else {
// 		// DER format
// 		cert, err = x509.ParseCertificate(certData)
// 		if err != nil {
// 			// If DER parsing fails, try PEM decoding again just in case
// 			if block, _ := pem.Decode(certData); block != nil {
// 				cert, err = x509.ParseCertificate(block.Bytes)
// 				if err != nil {
// 					return fmt.Errorf("parsing certificate (PEM fallback): %w", err)
// 				}
// 			} else {
// 				return fmt.Errorf("parsing DER certificate: %w", err)
// 			}
// 		}
// 	}

// 	// Read private key file
// 	keyData, err := os.ReadFile(keyPath)
// 	if err != nil {
// 		return fmt.Errorf("reading private key file: %w", err)
// 	}

// 	// Parse private key - handle different PEM formats and DER
// 	var privateKey any
// 	block, _ = pem.Decode(keyData)
// 	if block != nil {
// 		// PEM format key
// 		switch block.Type {
// 		case "RSA PRIVATE KEY":
// 			privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
// 			if err != nil {
// 				return fmt.Errorf("parsing PKCS1 private key: %w", err)
// 			}
// 		case "PRIVATE KEY": // PKCS#8
// 			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
// 			if err != nil {
// 				return fmt.Errorf("parsing PKCS8 private key: %w", err)
// 			}
// 		// TODO: Add cases for other key types like EC PRIVATE KEY if needed
// 		default:
// 			return fmt.Errorf("unsupported PEM block type for private key: %s", block.Type)
// 		}
// 	} else {
// 		// Try to decode as PKCS#8 DER format first (more common)
// 		privateKey, err = x509.ParsePKCS8PrivateKey(keyData)
// 		if err != nil {
// 			// If PKCS#8 fails, try PKCS#1 DER format
// 			privateKey, err = x509.ParsePKCS1PrivateKey(keyData)
// 			if err != nil {
// 				return fmt.Errorf("parsing private key (DER PKCS8/PKCS1): %w", err)
// 			}
// 		}
// 	}

// 	// Ensure the key is usable by the Encode function
// 	switch pk := privateKey.(type) {
// 	case *rsa.PrivateKey:
// 		// Key is RSA, which is supported
// 	case *ecdsa.PrivateKey:
// 		// Key is ECDSA, which is supported
// 	default:
// 		return fmt.Errorf("unsupported private key type: %T", pk)
// 	}

// 	// Create PKCS#12 data using the SSLMate library's Encode function
// 	pfxData, err := pkcs12.Modern.Encode(privateKey, cert, nil, password)
// 	if err != nil {
// 		return fmt.Errorf("encoding PKCS#12 data: %w", err)
// 	}

// 	// Write the PKCS#12 data to file
// 	if err := os.WriteFile(p12Path, pfxData, 0600); err != nil {
// 		return fmt.Errorf("writing P12 file: %w", err)
// 	}

// 	log.Infof("Successfully exported certificate and key to %s", p12Path)
// 	return nil
// }
