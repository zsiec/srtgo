package srt

import "testing"

func TestParseStreamID(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		wantOK   bool
		wantInfo StreamIDInfo
	}{
		{
			name:   "full access control",
			raw:    "#!::u=admin,r=live/stream,m=publish,t=stream,h=srt.example.com,s=sess123",
			wantOK: true,
			wantInfo: StreamIDInfo{
				UserName:     "admin",
				ResourceName: "live/stream",
				HostName:     "srt.example.com",
				SessionID:    "sess123",
				Type:         StreamTypeStream,
				Mode:         StreamModePublish,
			},
		},
		{
			name:   "subset of keys",
			raw:    "#!::r=live/test,m=request",
			wantOK: true,
			wantInfo: StreamIDInfo{
				ResourceName: "live/test",
				Mode:         StreamModeRequest,
			},
		},
		{
			name:   "non-standard keys in Extra",
			raw:    "#!::r=live/test,x-token=abc123,x-region=us-east",
			wantOK: true,
			wantInfo: StreamIDInfo{
				ResourceName: "live/test",
				Extra: map[string]string{
					"x-token":  "abc123",
					"x-region": "us-east",
				},
			},
		},
		{
			name:   "bare path",
			raw:    "live/stream",
			wantOK: true,
			wantInfo: StreamIDInfo{
				ResourceName: "live/stream",
			},
		},
		{
			name:   "empty string",
			raw:    "",
			wantOK: true,
			wantInfo: StreamIDInfo{
				ResourceName: "",
			},
		},
		{
			name:   "prefix only",
			raw:    "#!::",
			wantOK: false,
		},
		{
			name:   "malformed pairs skipped",
			raw:    "#!::r=live/test,badfield,=noval,m=publish",
			wantOK: true,
			wantInfo: StreamIDInfo{
				ResourceName: "live/test",
				Mode:         StreamModePublish,
			},
		},
		{
			name:   "empty value valid",
			raw:    "#!::r=,u=admin",
			wantOK: true,
			wantInfo: StreamIDInfo{
				ResourceName: "",
				UserName:     "admin",
			},
		},
		{
			name:   "bidirectional mode",
			raw:    "#!::m=bidirectional,t=file",
			wantOK: true,
			wantInfo: StreamIDInfo{
				Mode: StreamModeBidirectional,
				Type: StreamTypeFile,
			},
		},
		{
			name:   "auth type",
			raw:    "#!::t=auth,u=admin",
			wantOK: true,
			wantInfo: StreamIDInfo{
				Type:     StreamTypeAuth,
				UserName: "admin",
			},
		},
		{
			name:   "all malformed",
			raw:    "#!::badfield,=noval",
			wantOK: false,
		},
		{
			name:   "single key",
			raw:    "#!::u=viewer",
			wantOK: true,
			wantInfo: StreamIDInfo{
				UserName: "viewer",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, ok := ParseStreamID(tt.raw)
			if ok != tt.wantOK {
				t.Fatalf("ParseStreamID(%q): ok=%v, want %v", tt.raw, ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if info.UserName != tt.wantInfo.UserName {
				t.Errorf("UserName: got %q, want %q", info.UserName, tt.wantInfo.UserName)
			}
			if info.ResourceName != tt.wantInfo.ResourceName {
				t.Errorf("ResourceName: got %q, want %q", info.ResourceName, tt.wantInfo.ResourceName)
			}
			if info.HostName != tt.wantInfo.HostName {
				t.Errorf("HostName: got %q, want %q", info.HostName, tt.wantInfo.HostName)
			}
			if info.SessionID != tt.wantInfo.SessionID {
				t.Errorf("SessionID: got %q, want %q", info.SessionID, tt.wantInfo.SessionID)
			}
			if info.Type != tt.wantInfo.Type {
				t.Errorf("Type: got %q, want %q", info.Type, tt.wantInfo.Type)
			}
			if info.Mode != tt.wantInfo.Mode {
				t.Errorf("Mode: got %q, want %q", info.Mode, tt.wantInfo.Mode)
			}
			// Check Extra map
			if len(info.Extra) != len(tt.wantInfo.Extra) {
				t.Errorf("Extra: got %d keys, want %d", len(info.Extra), len(tt.wantInfo.Extra))
			}
			for k, wantV := range tt.wantInfo.Extra {
				if gotV, exists := info.Extra[k]; !exists || gotV != wantV {
					t.Errorf("Extra[%q]: got %q, want %q", k, gotV, wantV)
				}
			}
		})
	}
}
