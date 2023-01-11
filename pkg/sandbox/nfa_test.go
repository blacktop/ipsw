package sandbox

import (
	"testing"

	"github.com/blacktop/ipsw/internal/utils"
)

func TestNFA_ToRegex(t *testing.T) {
	tests := []struct {
		name    string
		regex   Regex
		want    []string
		wantErr bool
	}{
		{
			name: "test_1",
			regex: Regex{
				Version: 3,
				Length:  37,
				Data:    []byte{25, 2, 103, 2, 100, 2, 116, 2, 45, 59, 48, 57, 65, 90, 97, 122, 47, 22, 0, 10, 9, 0, 2, 45, 47, 32, 0, 2, 99, 41, 21, 0, 2, 115, 10, 29, 0},
			},
			want:    []string{"^gdt-[0-9A-Za-z]+-(s|c)$", "^gdt-[0-9A-Za-z]+-(c|s)$"},
			wantErr: false,
		},
		{
			name: "test_2",
			regex: Regex{
				Version: 3,
				Length:  183,
				Data:    []byte{25, 2, 47, 2, 112, 2, 114, 2, 105, 2, 118, 2, 97, 2, 116, 2, 101, 2, 47, 2, 118, 2, 97, 2, 114, 2, 47, 47, 159, 0, 47, 143, 0, 47, 121, 0, 2, 109, 2, 111, 2, 98, 2, 105, 2, 108, 2, 101, 2, 47, 2, 77, 2, 101, 2, 100, 2, 105, 2, 97, 2, 47, 47, 76, 0, 27, 48, 46, 47, 74, 0, 10, 65, 0, 2, 47, 2, 105, 2, 84, 2, 117, 2, 110, 2, 101, 2, 115, 2, 95, 2, 67, 2, 111, 2, 110, 2, 116, 2, 114, 2, 111, 2, 108, 2, 47, 2, 105, 2, 84, 2, 117, 2, 110, 2, 101, 2, 115, 41, 21, 0, 2, 101, 2, 117, 2, 115, 2, 101, 2, 114, 27, 48, 57, 47, 140, 0, 10, 131, 0, 10, 48, 0, 59, 45, 45, 48, 57, 65, 70, 47, 156, 0, 10, 143, 0, 10, 48, 0, 2, 85, 2, 115, 2, 101, 2, 114, 2, 115, 2, 47, 27, 48, 46, 47, 180, 0, 10, 171, 0, 10, 48, 0},
			},
			want:    []string{"^/private/var/(((mobile|euser[0-9]+)|[-0-9A-F]+)|Users/[^/]+)/Media/([^/]+/)?iTunes_Control/iTunes$"},
			wantErr: false,
		},
		{
			name: "test_3",
			regex: Regex{
				Version: 3,
				Length:  272,
				Data:    []byte{25, 2, 47, 2, 112, 2, 114, 2, 105, 2, 118, 2, 97, 2, 116, 2, 101, 2, 47, 2, 118, 2, 97, 2, 114, 2, 47, 47, 248, 0, 47, 232, 0, 47, 210, 0, 2, 109, 2, 111, 2, 98, 2, 105, 2, 108, 2, 101, 2, 47, 2, 77, 2, 101, 2, 100, 2, 105, 2, 97, 2, 47, 47, 76, 0, 27, 48, 46, 47, 74, 0, 10, 65, 0, 2, 47, 2, 105, 2, 84, 2, 117, 2, 110, 2, 101, 2, 115, 2, 95, 2, 67, 2, 111, 2, 110, 2, 116, 2, 114, 2, 111, 2, 108, 2, 47, 2, 105, 2, 84, 2, 117, 2, 110, 2, 101, 2, 115, 2, 47, 2, 77, 2, 101, 2, 100, 2, 105, 2, 97, 2, 76, 2, 105, 2, 98, 2, 114, 2, 97, 2, 114, 2, 121, 9, 2, 115, 2, 113, 2, 108, 2, 105, 2, 116, 2, 101, 2, 100, 2, 98, 47, 186, 0, 47, 199, 0, 47, 188, 0, 2, 45, 2, 106, 2, 111, 2, 117, 2, 114, 2, 110, 2, 97, 2, 108, 21, 0, 2, 45, 2, 115, 2, 104, 2, 109, 10, 186, 0, 2, 45, 2, 119, 2, 97, 2, 108, 10, 186, 0, 2, 101, 2, 117, 2, 115, 2, 101, 2, 114, 27, 48, 57, 47, 229, 0, 10, 220, 0, 10, 48, 0, 59, 45, 45, 48, 57, 65, 70, 47, 245, 0, 10, 232, 0, 10, 48, 0, 2, 85, 2, 115, 2, 101, 2, 114, 2, 115, 2, 47, 27, 48, 46, 47, 13, 1, 10, 4, 1, 10, 48, 0},
			},
			want: []string{
				"^/private/var/(((((((mobile|euser[0-9]+)/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb(((-journal|-shm)|-wal))?|[-0-9A-F]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb(-journal|-shm))|[-0-9A-F]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb-wal)|[-0-9A-F]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb|Users/[^/]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb(-journal|-shm))|Users/[^/]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb-wal)|Users/[^/]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb)",
				"^/private/var/(((((((mobile|euser[0-9]+)/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb(((-shm|-journal)|-wal))?|[-0-9A-F]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb(-shm|-journal))|[-0-9A-F]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb-wal)|[-0-9A-F]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb|Users/[^/]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb(-shm|-journal))|Users/[^/]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb-wal)|Users/[^/]+/Media/([^/]+/)?iTunes_Control/iTunes/MediaLibrary.sqlitedb)",
			},
			wantErr: false,
		},
		{
			name: "test_4",
			regex: Regex{
				Version: 3,
				Length:  166,
				Data:    []byte{25, 2, 47, 2, 112, 2, 114, 2, 105, 2, 118, 2, 97, 2, 116, 2, 101, 2, 47, 2, 118, 2, 97, 2, 114, 2, 47, 2, 99, 2, 111, 2, 110, 2, 116, 2, 97, 2, 105, 2, 110, 2, 101, 2, 114, 2, 115, 2, 47, 2, 66, 2, 117, 2, 110, 2, 100, 2, 108, 2, 101, 2, 47, 27, 48, 46, 47, 72, 0, 10, 63, 0, 2, 47, 59, 45, 45, 48, 57, 65, 90, 47, 87, 0, 10, 74, 0, 2, 47, 2, 67, 2, 108, 2, 97, 2, 115, 2, 115, 2, 114, 2, 111, 2, 111, 2, 109, 9, 2, 97, 2, 112, 2, 112, 21, 0},
			},
			want:    []string{"^/private/var/containers/Bundle/[^/]+/[-0-9A-Z]+/Classroom.app"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nfa, err := tt.regex.NFA()
			if (err != nil) != tt.wantErr {
				t.Errorf("NFA.ToRegex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			got, err := nfa.ToRegex()
			if (err != nil) != tt.wantErr {
				t.Errorf("NFA.ToRegex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !utils.StrSliceContains(tt.want, got) {
				t.Errorf("NFA.ToRegex() = %v, want %v", got, tt.want)
			}
		})
	}
}
