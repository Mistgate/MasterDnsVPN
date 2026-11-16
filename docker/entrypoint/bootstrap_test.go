package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func testSettings(t *testing.T) settings {
	t.Helper()
	root := t.TempDir()
	s := settings{
		appDir:     filepath.Join(root, "app"),
		dataDir:    filepath.Join(root, "data"),
		configFile: "server_config.toml",
		domain:     "vpn.example.com",
		template:   filepath.Join(root, "sample.toml"),
	}
	writeTestFile(t, filepath.Join(s.appDir, "masterdnsvpn"), "fake server")
	writeTestFile(t, s.template, "DOMAIN = [\"sample.example.com\"]\nDEVICE_CREDENTIAL = \"0102030405060708.0000000000000000000000000000000000000000000000000000000000000000\"\nUDP_PORT = 53\n")
	return s
}

func writeTestFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func argumentValue(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func TestPrepareFirstBootPersistsConfigAndLaunchesServer(t *testing.T) {
	s := testSettings(t)
	s.domain = `vpn$1&"quoted"\path.example.com`
	launch, err := prepare(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(s.appDir, s.configFile)
	configData := readTestFile(t, configPath)
	var decoded struct {
		Domain           []string `toml:"DOMAIN"`
		DeviceCredential string   `toml:"DEVICE_CREDENTIAL"`
		UDPPort          int      `toml:"UDP_PORT"`
	}
	if _, err := toml.Decode(configData, &decoded); err != nil {
		t.Fatalf("generated config is invalid TOML: %v", err)
	}
	if !reflect.DeepEqual(decoded.Domain, []string{s.domain}) || decoded.UDPPort != 53 || decoded.DeviceCredential == "" {
		t.Fatalf("generated config fields are wrong: %+v", decoded)
	}
	if got := readTestFile(t, persistentPath(s, configPath)); got != configData {
		t.Fatal("expected generated config to be persisted")
	}
	if launch.path != filepath.Join(s.appDir, "masterdnsvpn") || launch.dir != s.appDir {
		t.Fatalf("unexpected launch target: %+v", launch)
	}
	if argumentValue(launch.args, "-config") != configPath {
		t.Fatalf("launch did not use generated config path: %v", launch.args)
	}
	for _, arg := range launch.args {
		if arg == "-genkey" || arg == "-encryption-key-file" {
			t.Fatalf("legacy key setup argument remains: %v", launch.args)
		}
	}
}

func TestPrepareRestartRestoresPersistedConfigWithoutKeyFiles(t *testing.T) {
	s := testSettings(t)
	first, err := prepare(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	configPath := argumentValue(first.args, "-config")
	want := readTestFile(t, configPath)
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	s.domain = ""
	second, err := prepare(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := readTestFile(t, argumentValue(second.args, "-config")); got != want {
		t.Fatal("restart did not restore the persisted server config")
	}
}

func TestPrepareConfigOverrideAndRemainingFlags(t *testing.T) {
	s := testSettings(t)
	custom := filepath.Join("custom", "server.toml")
	launch, err := prepare(s, []string{"-config", custom, "-udp-port", "15353", "--", "-domain", "ignored"})
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(s.appDir, custom)
	if argumentValue(launch.args, "-config") != configPath {
		t.Fatalf("config override was not canonicalized: %v", launch.args)
	}
	if !reflect.DeepEqual(launch.args[len(launch.args)-4:], []string{"-udp-port", "15353", "--", "-domain"}) {
		// The final positional value is also preserved after --.
		if !reflect.DeepEqual(launch.args[len(launch.args)-5:], []string{"-udp-port", "15353", "--", "-domain", "ignored"}) {
			t.Fatalf("remaining server flags changed order: %v", launch.args)
		}
	}
}

func TestPrepareBase64ConfigPersistsAndRestores(t *testing.T) {
	s := testSettings(t)
	document := map[string]any{
		"DOMAIN":            []string{"incoming.example.com"},
		"DEVICE_CREDENTIAL": "0102030405060708.0000000000000000000000000000000000000000000000000000000000000000",
	}
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	launch, err := prepare(s, []string{"-json_base64", encoded})
	if err != nil {
		t.Fatal(err)
	}
	configPath := argumentValue(launch.args, "-config")
	if filepath.Ext(configPath) != ".json" {
		t.Fatalf("expected JSON fallback path, got %s", configPath)
	}
	if err := os.Remove(configPath); err != nil {
		t.Fatal(err)
	}
	s.domain = ""
	restarted, err := prepare(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := argumentValue(restarted.args, "-config"); filepath.Ext(got) != ".json" {
		t.Fatalf("restart did not restore the persisted JSON config: %s", got)
	}
}

func TestPrepareRejectsConflictingJSONSourcesBeforeWriting(t *testing.T) {
	s := testSettings(t)
	_, err := prepare(s, []string{"-j", "config.json", "-json-base64", "e30="})
	if err == nil {
		t.Fatal("expected conflicting JSON sources to be rejected")
	}
	if _, err := os.Stat(s.dataDir); !os.IsNotExist(err) {
		t.Fatalf("expected no state directory to be created before validation, got %v", err)
	}
}

func TestPrepareConfigFlagSelectsFilesForRestoreAndPersistence(t *testing.T) {
	s := testSettings(t)
	s.domain = ""
	configName := filepath.Join("selected", "server.toml")
	config := "DOMAIN = [\"selected.example.com\"]\nDEVICE_CREDENTIAL = \"0102030405060708.0000000000000000000000000000000000000000000000000000000000000000\"\n"
	persistedPath := filepath.Join(s.dataDir, configName)
	writeTestFile(t, persistedPath, config)

	launch, err := prepare(s, []string{"-config", "superseded.toml", "--config=selected/server.toml", "-udp-port", "15353"})
	if err != nil {
		t.Fatal(err)
	}
	selectedPath := filepath.Join(s.appDir, configName)
	if argumentValue(launch.args, "-config") != selectedPath {
		t.Fatalf("incorrect effective config path: %q", argumentValue(launch.args, "-config"))
	}
	if got := readTestFile(t, selectedPath); got != config {
		t.Fatalf("selected persisted config changed: %q", got)
	}
	if got := readTestFile(t, persistedPath); got != config {
		t.Fatalf("selected config persistence changed: %q", got)
	}
	if _, err := os.Stat(filepath.Join(s.appDir, s.configFile)); !os.IsNotExist(err) {
		t.Fatalf("default config unexpectedly created: %v", err)
	}
}

func TestPrepareConfigInsideDataDirectoryPersistsInPlace(t *testing.T) {
	s := testSettings(t)
	s.domain = ""
	configPath := filepath.Join(s.dataDir, "mounted", "server.toml")
	config := "DOMAIN = [\"mounted.example.com\"]\nDEVICE_CREDENTIAL = \"0102030405060708.0000000000000000000000000000000000000000000000000000000000000000\"\n"
	writeTestFile(t, configPath, config)

	launch, err := prepare(s, []string{"-config", configPath})
	if err != nil {
		t.Fatal(err)
	}
	if argumentValue(launch.args, "-config") != configPath {
		t.Fatalf("mounted config path was not retained: %#v", launch.args)
	}
	if got := readTestFile(t, configPath); got != config {
		t.Fatalf("mounted config changed: %q", got)
	}
}

func TestPrepareJSONFileAliasesSelectConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		file string
	}{
		{"primary wins", []string{"-json", "json/primary.json", "-j", "json/alias.json"}, "primary"},
		{"alias", []string{"--j=json/alias.json"}, "alias"},
		{"empty primary uses alias", []string{"-j", "json/alias.json", "--json="}, "alias"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSettings(t)
			s.domain = ""
			for _, name := range []string{"primary", "alias"} {
				writeTestFile(t, filepath.Join(s.dataDir, "json", name+".json"), `{"DOMAIN":["saved.example.com"]}`)
			}
			launch, err := prepare(s, append([]string{"-config", "unused.toml"}, tc.args...))
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(s.appDir, "json", tc.file+".json")
			if got := argumentValue(launch.args, "-config"); got != want {
				t.Fatalf("JSON source was not selected: got=%q want=%q", got, want)
			}
			if got := readTestFile(t, want); got != `{"DOMAIN":["saved.example.com"]}` {
				t.Fatalf("selected JSON config changed: %s", got)
			}
		})
	}
}

func TestPrepareBase64ConfigOverridesPersistedJSONAndSurvivesRestart(t *testing.T) {
	document := `{"DEVICE_CREDENTIAL":"0102030405060708.0000000000000000000000000000000000000000000000000000000000000000","DOMAIN":["incoming.example.com"]}`
	encoded := base64.StdEncoding.EncodeToString([]byte(document))
	for _, args := range [][]string{
		{"-json_base64", encoded, "-json-base64", "ignored-invalid-alias"},
		{"--json-base64=" + encoded},
	} {
		t.Run(args[0], func(t *testing.T) {
			s := testSettings(t)
			s.domain = ""
			writeTestFile(t, filepath.Join(s.dataDir, "server_config.json"), `{"DOMAIN":["stale.example.com"]}`)
			launch, err := prepare(s, args)
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(s.appDir, "server_config.json")
			if argumentValue(launch.args, "-config") != configPath {
				t.Fatalf("base64 config was not canonicalized: %#v", launch.args)
			}
			if got := readTestFile(t, configPath); got != document {
				t.Fatalf("incoming base64 config did not replace stale config: %s", got)
			}
			if got := readTestFile(t, filepath.Join(s.dataDir, "server_config.json")); got != document {
				t.Fatalf("incoming base64 config was not persisted: %s", got)
			}

			s.appDir = filepath.Join(t.TempDir(), "replacement-app")
			writeTestFile(t, filepath.Join(s.appDir, "masterdnsvpn"), "fake server")
			restarted, err := prepare(s, nil)
			if err != nil {
				t.Fatal(err)
			}
			restoredPath := argumentValue(restarted.args, "-config")
			if restoredPath != filepath.Join(s.appDir, "server_config.json") || readTestFile(t, restoredPath) != document {
				t.Fatal("restart did not restore the incoming JSON config")
			}
		})
	}
}

func TestPrepareReportsStartupFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(*testing.T, *settings)
		want   string
	}{
		{"missing domain", func(_ *testing.T, s *settings) { s.domain = "" }, "DOMAIN env is required"},
		{"missing binary", func(t *testing.T, s *settings) {
			if err := os.Remove(filepath.Join(s.appDir, "masterdnsvpn")); err != nil {
				t.Fatal(err)
			}
		}, "server binary is missing"},
		{"missing template", func(t *testing.T, s *settings) { s.template = filepath.Join(t.TempDir(), "missing.toml") }, "read bundled configuration"},
		{"invalid template", func(t *testing.T, s *settings) { writeTestFile(t, s.template, "UDP_PORT = 53\n") }, "bundled configuration has no DOMAIN"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testSettings(t)
			tc.change(t, &s)
			_, err := prepare(s, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got error %v, want substring %q", err, tc.want)
			}
		})
	}
}
