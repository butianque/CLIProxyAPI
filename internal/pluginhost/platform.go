package pluginhost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

var (
	pluginIDPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	pluginVersionPattern = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)
)

type pluginFile struct {
	ID      string
	Path    string
	Version string
}

// PluginFileInfo describes a plugin binary selected by the host discovery rules.
type PluginFileInfo struct {
	ID      string
	Path    string
	Version string
}

// ValidatePluginID reports whether id can be used as a plugin configuration key.
func ValidatePluginID(id string) bool {
	return validPluginID(id)
}

func validPluginID(id string) bool {
	return pluginIDPattern.MatchString(id)
}

func validPluginVersion(version string) bool {
	return version != "" && !strings.HasPrefix(version, "v") && pluginVersionPattern.MatchString(version)
}

func pluginIDFromPath(path string) string {
	file, ok := pluginFileFromPath(path, "")
	if ok {
		return file.ID
	}
	base := filepath.Base(path)
	lowerBase := strings.ToLower(base)
	for _, extension := range []string{".so", ".dylib", ".dll"} {
		if strings.HasSuffix(lowerBase, extension) {
			return base[:len(base)-len(extension)]
		}
	}
	return base
}

func pluginFileFromPath(filePath string, requiredExtension string) (pluginFile, bool) {
	base := filepath.Base(filePath)
	lowerBase := strings.ToLower(base)
	extension := strings.TrimSpace(requiredExtension)
	if extension != "" {
		if !strings.HasSuffix(lowerBase, strings.ToLower(extension)) {
			return pluginFile{}, false
		}
	} else {
		for _, candidateExtension := range []string{".so", ".dylib", ".dll"} {
			if strings.HasSuffix(lowerBase, candidateExtension) {
				extension = candidateExtension
				break
			}
		}
		if extension == "" {
			return pluginFile{}, false
		}
	}
	name := base[:len(base)-len(extension)]
	id := name
	version := ""
	if versionIndex := strings.LastIndex(name, "-v"); versionIndex > 0 {
		candidateID := name[:versionIndex]
		candidateVersion := name[versionIndex+2:]
		if validPluginID(candidateID) && validPluginVersion(candidateVersion) {
			id = candidateID
			version = candidateVersion
		}
	}
	if !validPluginID(id) {
		return pluginFile{}, false
	}
	return pluginFile{ID: id, Path: filePath, Version: version}, true
}

// PluginExtension returns the dynamic library file extension used for goos.
func PluginExtension(goos string) string {
	return pluginExtension(goos)
}

func pluginExtension(goos string) string {
	switch goos {
	case "darwin":
		return ".dylib"
	case "windows":
		return ".dll"
	default:
		return ".so"
	}
}

func selectPluginFiles(root string, desiredVersions ...map[string]string) ([]pluginFile, error) {
	selected, _, errSelect := selectPluginFilesWithCandidates(root, desiredVersions...)
	return selected, errSelect
}

func selectPluginFilesWithCandidates(root string, desiredVersions ...map[string]string) ([]pluginFile, []pluginFile, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "plugins"
	}
	desired := normalizeDesiredPluginVersions(desiredVersions...)

	candidates := candidateDirs(root, runtime.GOOS, runtime.GOARCH)
	extension := pluginExtension(runtime.GOOS)
	selectedByID := make(map[string]pluginFile)
	order := make([]string, 0)
	all := make([]pluginFile, 0)
	for _, dir := range candidates {
		entries, errReadDir := os.ReadDir(dir)
		if errReadDir != nil {
			if os.IsNotExist(errReadDir) {
				continue
			}
			return nil, nil, errReadDir
		}
		files := make([]string, 0, len(entries))
		for _, entry := range entries {
			if entry == nil || !entry.Type().IsRegular() {
				continue
			}
			if strings.HasSuffix(strings.ToLower(entry.Name()), extension) {
				files = append(files, filepath.Join(dir, entry.Name()))
			}
		}
		sort.Strings(files)
		for _, path := range files {
			file, okFile := pluginFileFromPath(path, extension)
			if !okFile {
				continue
			}
			all = append(all, file)
			current, exists := selectedByID[file.ID]
			if !exists {
				selectedByID[file.ID] = file
				order = append(order, file.ID)
				continue
			}
			if pluginFilePreferredForDesired(file, current, desired[file.ID]) {
				selectedByID[file.ID] = file
			}
		}
	}
	selected := make([]pluginFile, 0, len(order))
	for _, id := range order {
		file := selectedByID[id]
		if desiredVersion := desired[id]; desiredVersion != "" && file.Version != desiredVersion {
			continue
		}
		selected = append(selected, file)
	}
	return selected, all, nil
}

func normalizeDesiredPluginVersions(sources ...map[string]string) map[string]string {
	out := make(map[string]string)
	for _, source := range sources {
		for id, version := range source {
			id = strings.TrimSpace(id)
			version = normalizePluginDesiredVersion(version)
			if id == "" || version == "" {
				continue
			}
			out[id] = version
		}
	}
	return out
}

func pluginFilePreferredForDesired(candidate pluginFile, current pluginFile, desiredVersion string) bool {
	desiredVersion = normalizePluginDesiredVersion(desiredVersion)
	if desiredVersion != "" {
		candidateMatches := candidate.Version == desiredVersion
		currentMatches := current.Version == desiredVersion
		if candidateMatches != currentMatches {
			return candidateMatches
		}
	}
	return pluginFilePreferred(candidate, current)
}

func pluginFilePreferred(candidate pluginFile, current pluginFile) bool {
	if candidate.Version == "" {
		return false
	}
	if current.Version == "" {
		return true
	}
	comparison, comparable := comparePluginVersions(candidate.Version, current.Version)
	if !comparable {
		return candidate.Version > current.Version
	}
	return comparison > 0
}

func comparePluginVersions(a, b string) (int, bool) {
	segmentsA := strings.Split(a, ".")
	segmentsB := strings.Split(b, ".")
	length := len(segmentsA)
	if len(segmentsB) > length {
		length = len(segmentsB)
	}
	for index := 0; index < length; index++ {
		numberA, okA := pluginVersionSegment(segmentsA, index)
		numberB, okB := pluginVersionSegment(segmentsB, index)
		if !okA || !okB {
			return 0, false
		}
		if numberA != numberB {
			if numberA < numberB {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}

func pluginVersionSegment(segments []string, index int) (int64, bool) {
	if index >= len(segments) {
		return 0, true
	}
	number, errParse := strconv.ParseInt(segments[index], 10, 64)
	if errParse != nil || number < 0 {
		return 0, false
	}
	return number, true
}

// PluginDirs returns the directories the host scans for plugin libraries, most
// specific first.
//
// Only directories that exist are returned. A watch on a directory that is not
// there yet would either fail or silently cover a layout the operator does not
// use, so the caller is handed the real scan roots instead of a guess.
func PluginDirs(root string) []string {
	root = strings.TrimSpace(root)
	if root == "" {
		root = "plugins"
	}
	dirs := make([]string, 0, 2)
	for _, dir := range candidateDirs(root, runtime.GOOS, runtime.GOARCH) {
		info, errStat := os.Stat(dir)
		if errStat != nil || !info.IsDir() {
			continue
		}
		dirs = append(dirs, dir)
	}
	return dirs
}

// pluginFileFingerprint returns a content fingerprint for a plugin binary.
//
// A rebuild that keeps its version in the filename produces a different library
// at the same path, so the path alone cannot say whether the loaded library is
// still the one on disk. The fingerprint is what the host remembers and compares.
func pluginFileFingerprint(path string) (string, error) {
	file, errOpen := os.Open(path)
	if errOpen != nil {
		return "", errOpen
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			log.WithError(errClose).Debugf("pluginhost: failed to close plugin file %s", path)
		}
	}()
	hasher := sha256.New()
	if _, errCopy := io.Copy(hasher, file); errCopy != nil {
		return "", errCopy
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// pluginFileReplaced reports whether the file at path is no longer the content
// the host loaded.
//
// An unreadable file reports false. The load path owns that error, and a plugin
// whose file vanished is still the one being served, so treating it as a
// replacement would drop a working plugin on a transient read failure.
func pluginFileReplaced(path, loadedFingerprint string) bool {
	if loadedFingerprint == "" {
		return false
	}
	current, errFingerprint := pluginFileFingerprint(path)
	if errFingerprint != nil {
		log.WithError(errFingerprint).Debugf("pluginhost: cannot fingerprint plugin file %s", path)
		return false
	}
	return current != loadedFingerprint
}

// pluginFingerprintPrefix shortens a fingerprint for log output. The full value
// is only useful for comparison, which logs do not need.
func pluginFingerprintPrefix(fingerprint string) string {
	const prefixLength = 12
	if len(fingerprint) <= prefixLength {
		return fingerprint
	}
	return fingerprint[:prefixLength]
}

// cleanupUnselectedPluginFiles removes plugin files that a loaded file has
// provably superseded.
//
// Only a strictly older version of the same plugin is deleted. A file that is
// newer than the loaded one is kept and logged, because that combination means
// the host is not running the newest artifact on disk (a pinned
// `plugins.configs.<id>.version`, or a load that failed), and deleting it would
// destroy the very file the operator just dropped in. Files with no version
// segment, or versions that cannot be ordered, are kept for the same reason.
func cleanupUnselectedPluginFiles(root string, loaded []pluginFile) error {
	if len(loaded) == 0 {
		return nil
	}
	_, candidates, errSelect := selectPluginFilesWithCandidates(root)
	if errSelect != nil {
		return errSelect
	}
	loadedByID := make(map[string][]pluginFile, len(loaded))
	for _, file := range loaded {
		if strings.TrimSpace(file.ID) == "" || strings.TrimSpace(file.Path) == "" {
			continue
		}
		loadedByID[file.ID] = append(loadedByID[file.ID], file)
	}
	var errs []error
	for _, candidate := range candidates {
		loadedFiles := loadedByID[candidate.ID]
		if len(loadedFiles) == 0 {
			continue
		}
		candidatePath := filepath.Clean(candidate.Path)
		selected := false
		for _, file := range loadedFiles {
			if filepath.Clean(file.Path) == candidatePath {
				selected = true
				break
			}
		}
		if selected {
			continue
		}
		supersededBy, superseded := supersededPluginVersion(candidate.Version, loadedFiles)
		if !superseded {
			log.WithFields(pluginLogFields(candidate.ID, "", candidate.Version, candidate.Path)).
				Warn("pluginhost: keeping plugin file that is not older than the loaded one")
			continue
		}
		if errRemove := os.Remove(candidate.Path); errRemove != nil && !errors.Is(errRemove, os.ErrNotExist) {
			errs = append(errs, errRemove)
			log.WithError(errRemove).Warnf("pluginhost: failed to remove old plugin file %s", candidate.Path)
			continue
		}
		fields := pluginLogFields(candidate.ID, "", candidate.Version, candidate.Path)
		fields["superseded_by"] = supersededBy
		log.WithFields(fields).Info("pluginhost: old plugin file removed")
	}
	return errors.Join(errs...)
}

// supersededPluginVersion reports whether version is strictly older than a
// version among loaded, and returns the loaded version that supersedes it.
func supersededPluginVersion(version string, loaded []pluginFile) (string, bool) {
	if version == "" {
		return "", false
	}
	for _, file := range loaded {
		if file.Version == "" {
			continue
		}
		comparison, comparable := comparePluginVersions(version, file.Version)
		if comparable && comparison < 0 {
			return file.Version, true
		}
	}
	return "", false
}

// DiscoverPluginFiles returns plugin binaries selected by the current host discovery rules.
func DiscoverPluginFiles(root string, desiredVersions ...map[string]string) ([]PluginFileInfo, error) {
	files, errSelect := selectPluginFiles(root, desiredVersions...)
	if errSelect != nil {
		return nil, errSelect
	}
	out := make([]PluginFileInfo, 0, len(files))
	for _, file := range files {
		out = append(out, PluginFileInfo{
			ID:      file.ID,
			Path:    file.Path,
			Version: file.Version,
		})
	}
	return out, nil
}

func candidateDirs(root, goos, goarch string) []string {
	dirs := make([]string, 0, 2)
	dirs = append(dirs, filepath.Join(root, goos, goarch))
	dirs = append(dirs, root)
	return dirs
}
