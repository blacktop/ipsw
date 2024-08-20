package utils

import (
	"reflect"
	"testing"
)

func TestDifference(t *testing.T) {
	type args struct {
		a []string
		b []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"b", "c", "d"},
			},
			want: []string{"a"},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"b", "c", "d"},
				b: []string{"a", "b", "c"},
			},
			want: []string{"d"},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"a", "b", "c"},
			},
			want: []string{},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"d", "e", "f"},
			},
			want: []string{"a", "b", "c"},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"c", "b", "a"},
			},
			want: []string{},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"a", "b", "c"},
				b: []string{"c", "b", "a", "d"},
			},
			want: []string{},
		},
		{
			name: "Test Difference",
			args: args{
				a: []string{"c", "b", "a", "d"},
				b: []string{"a", "b", "c"},
			},
			want: []string{"d"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Difference(tt.args.a, tt.args.b); !reflect.DeepEqual(got, tt.want) {
				if len(got) != len(tt.want) {
					t.Errorf("Difference() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
