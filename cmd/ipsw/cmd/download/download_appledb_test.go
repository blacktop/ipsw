package download

import "testing"

func TestAppledbNoUpdateFlagWiring(t *testing.T) {
	f := downloadAppledbCmd.Flags().Lookup("no-update")
	if f == nil {
		t.Fatal("appledb command is missing the no-update flag")
	}
	if f.DefValue != "false" {
		t.Fatalf("no-update default = %s, want false (update behavior preserved)", f.DefValue)
	}
}
