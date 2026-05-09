package cmd

import "testing"

func TestParseEntXrefsInputs(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		dscFlag    string
		wantKernel string
		wantDSC    string
		wantErr    bool
	}{
		{name: "kernel only", args: []string{"kernelcache"}, wantKernel: "kernelcache"},
		{name: "both positional", args: []string{"kernelcache", "dyld_shared_cache_arm64e"}, wantKernel: "kernelcache", wantDSC: "dyld_shared_cache_arm64e"},
		{name: "dsc only", dscFlag: "dyld_shared_cache_arm64e", wantDSC: "dyld_shared_cache_arm64e"},
		{name: "kernel plus dsc flag", args: []string{"kernelcache"}, dscFlag: "dyld_shared_cache_arm64e", wantKernel: "kernelcache", wantDSC: "dyld_shared_cache_arm64e"},
		{name: "no inputs", wantErr: true},
		{name: "too many with dsc flag", args: []string{"kernelcache", "extra"}, dscFlag: "dyld_shared_cache_arm64e", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKernel, gotDSC, err := parseEntXrefsInputs(tt.args, tt.dscFlag)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if gotKernel != tt.wantKernel || gotDSC != tt.wantDSC {
				t.Fatalf("got kernel=%q dsc=%q, want kernel=%q dsc=%q", gotKernel, gotDSC, tt.wantKernel, tt.wantDSC)
			}
		})
	}
}
