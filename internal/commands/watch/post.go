package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Release struct {
	MajorRelease string `json:"major_release,omitempty"`
	Release      string `json:"release,omitempty"`
	Projects     []struct {
		Project string `json:"project,omitempty"`
		Tag     string `json:"tag,omitempty"`
	} `json:"projects,omitempty"`
}

func (r Release) GetProjectTag(project string) (string, error) {
	for _, release := range r.Projects {
		if release.Project == project {
			return release.Tag, nil
		}
	}
	return "", fmt.Errorf("no tag found for %s", project)
}

func getRelease(tag string) (*Release, error) {
	releaseURL := fmt.Sprintf("https://raw.githubusercontent.com/apple-oss-distributions/distribution-macOS/refs/tags/%s/release.json", tag)
	resp, err := http.Get(releaseURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get release.json: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var release Release
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, err
	}

	return &release, nil
}

func Post(prevTag, newTag string) (string, error) {
	prevReleases, err := getRelease(prevTag)
	if err != nil {
		return "", err
	}

	newReleases, err := getRelease(newTag)
	if err != nil {
		return "", err
	}

	post := fmt.Sprintf("NEW %s 🥫🍝 sauce! 🎉\n\n", newReleases.Release)

	prevXnuTag, err := prevReleases.GetProjectTag("xnu")
	if err != nil {
		return "", err
	}

	newXnuTag, err := newReleases.GetProjectTag("xnu")
	if err != nil {
		return "", err
	}

	if prevXnuTag != newXnuTag {
		post += "xnu:\n"
		post += fmt.Sprintf("https://github.com/apple-oss-distributions/xnu/compare/%s...%s\n\n", prevXnuTag, newXnuTag)
	}

	prevDyldTag, err := prevReleases.GetProjectTag("dyld")
	if err != nil {
		return "", err
	}

	newDyldTag, err := newReleases.GetProjectTag("dyld")
	if err != nil {
		return "", err
	}

	if prevDyldTag != newDyldTag {
		post += "dyld:\n"
		post += fmt.Sprintf("https://github.com/apple-oss-distributions/dyld/compare/%s...%s\n\n", prevDyldTag, newDyldTag)
	}

	prevObjcTag, err := prevReleases.GetProjectTag("objc4")
	if err != nil {
		return "", err
	}

	newObjcTag, err := newReleases.GetProjectTag("objc4")
	if err != nil {
		return "", err
	}

	if prevObjcTag != newObjcTag {
		post += "objc4:\n"
		post += fmt.Sprintf("https://github.com/apple-oss-distributions/objc4/compare/%s...%s\n\n", prevObjcTag, newObjcTag)
	}

	prevSecurityTag, err := prevReleases.GetProjectTag("Security")
	if err != nil {
		return "", err
	}

	newSecurityTag, err := newReleases.GetProjectTag("Security")
	if err != nil {
		return "", err
	}

	if prevSecurityTag != newSecurityTag {
		post += "Security:\n"
		post += fmt.Sprintf("https://github.com/apple-oss-distributions/Security/compare/%s...%s\n\n", prevSecurityTag, newSecurityTag)
	}

	prevLibsystemTag, err := prevReleases.GetProjectTag("Libsystem")
	if err != nil {
		return "", err
	}

	newLibsystemTag, err := newReleases.GetProjectTag("Libsystem")
	if err != nil {
		return "", err
	}

	if prevLibsystemTag != newLibsystemTag {
		post += "Libsystem:\n"
		post += fmt.Sprintf("https://github.com/apple-oss-distributions/Libsystem/compare/%s...%s\n\n", prevLibsystemTag, newLibsystemTag)
	}

	prevLibcTag, err := prevReleases.GetProjectTag("Libc")
	if err != nil {
		return "", err
	}

	newLibcTag, err := newReleases.GetProjectTag("Libc")
	if err != nil {
		return "", err
	}

	if prevLibcTag != newLibcTag {
		post += "Libc:\n"
		post += fmt.Sprintf("https://github.com/apple-oss-distributions/Libc/compare/%s...%s\n\n", prevLibcTag, newLibcTag)
	}

	post += "  - this post was generated by `ipsw` 🤖"

	return post, nil
}
