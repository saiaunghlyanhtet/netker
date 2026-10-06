package container

import (
	"reflect"
	"testing"
)

func TestValidateNetworks(t *testing.T) {
	cases := []struct {
		in      []string
		want    []string
		wantErr bool
	}{
		{nil, []string{"netker"}, false},
		{[]string{"a", "b"}, []string{"a", "b"}, false},
		{[]string{"host"}, []string{"host"}, false},
		{[]string{"none"}, []string{"none"}, false},
		{[]string{"host", "a"}, nil, true},
		{[]string{"a", "none"}, nil, true},
		{[]string{"a", "a"}, nil, true},
		{[]string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"}, nil, true},
	}
	for _, c := range cases {
		got, err := validateNetworks(c.in)
		if (err != nil) != c.wantErr || (!c.wantErr && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("validateNetworks(%v) = %v, %v; want %v, err=%v", c.in, got, err, c.want, c.wantErr)
		}
	}
}
