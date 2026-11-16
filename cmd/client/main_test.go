package main

import (
	"bytes"
	"os"
	"testing"
)

func withClientTestArgs(t *testing.T, args []string, fn func()) {
	t.Helper()
	prev := os.Args
	os.Args = args
	t.Cleanup(func() {
		os.Args = prev
	})
	fn()
}

func TestParseClientCLIArgsAcceptsDefaultNoArgs(t *testing.T) {
	opts, overrides, err := parseClientCLIArgs(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseClientCLIArgs returned error: %v", err)
	}
	if opts.configPath != "client_config.toml" {
		t.Fatalf("unexpected default config path: got=%q want=%q", opts.configPath, "client_config.toml")
	}
	if overrides.ResolversFilePath != nil {
		t.Fatal("did not expect resolver override for default invocation")
	}
}

func TestParseClientCLIArgsAcceptsSinglePositionalConfigPath(t *testing.T) {
	opts, _, err := parseClientCLIArgs([]string{"./custom-client.toml"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseClientCLIArgs returned error: %v", err)
	}
	if opts.configPath != "./custom-client.toml" {
		t.Fatalf("unexpected positional config path: got=%q want=%q", opts.configPath, "./custom-client.toml")
	}
}

func TestParseClientCLIArgsAcceptsLegacyKeyAlias(t *testing.T) {
	_, overrides, err := parseClientCLIArgs([]string{"-credential", "0102030405060708.0000000000000000000000000000000000000000000000000000000000000000"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseClientCLIArgs returned error: %v", err)
	}
	got, ok := overrides.Values["DeviceCredential"].(string)
	if !ok || got != "0102030405060708.0000000000000000000000000000000000000000000000000000000000000000" {
		t.Fatalf("unexpected device credential override: %#v", overrides.Values["DeviceCredential"])
	}
}

func TestParseClientCLIArgsAcceptsPositionalConfigAndResolvers(t *testing.T) {
	opts, overrides, err := parseClientCLIArgs([]string{"./custom-client.toml", "./client_resolvers.txt"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseClientCLIArgs returned error: %v", err)
	}
	if opts.configPath != "./custom-client.toml" {
		t.Fatalf("unexpected positional config path: got=%q want=%q", opts.configPath, "./custom-client.toml")
	}
	if overrides.ResolversFilePath == nil {
		t.Fatal("expected positional resolvers path override")
	}
}

func TestParseClientCLIArgsAcceptsJSONBase64Mode(t *testing.T) {
	opts, overrides, err := parseClientCLIArgs([]string{"-json_base64", "Zm9v"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseClientCLIArgs returned error: %v", err)
	}
	if opts.jsonBase64 != "Zm9v" {
		t.Fatalf("unexpected json base64 payload: got=%q want=%q", opts.jsonBase64, "Zm9v")
	}
	if opts.jsonPath != "" {
		t.Fatalf("did not expect json file path in json base64 mode: %q", opts.jsonPath)
	}
	if overrides.ResolversFilePath != nil {
		t.Fatal("did not expect resolver override in json base64 mode")
	}
}

func TestParseClientCLIArgsIgnoresExecutableInjectedAsPositionalConfig(t *testing.T) {
	withClientTestArgs(t, []string{"/data/data/com.termux/files/home/MasterDNS/MasterDnsVPN_Client_Termux_ARM64"}, func() {
		opts, overrides, err := parseClientCLIArgs([]string{"/data/data/com.termux/files/home/MasterDNS/MasterDnsVPN_Client_Termux_ARM64"}, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("parseClientCLIArgs returned error: %v", err)
		}
		if opts.configPath != "client_config.toml" {
			t.Fatalf("unexpected config path after injected executable path: got=%q want=%q", opts.configPath, "client_config.toml")
		}
		if overrides.ResolversFilePath != nil {
			t.Fatal("did not expect resolver override when executable path is injected")
		}
	})
}
