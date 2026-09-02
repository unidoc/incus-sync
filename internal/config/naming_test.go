package config

import "testing"

func TestBaseName(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"lupin", false},
		{"jak-brave", false},
		{"web1", false},
		{"a", false},
		{"", true},
		{"UPPER", true},
		{"foo_bar", true},
		{"-leading-hyphen", true},
		{"trailing-hyphen-", true},
		{"double--hyphen", true},
		{"1starts-with-digit", true},
	}
	for _, tc := range cases {
		err := checkBaseName("test", tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("checkBaseName(%q) err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

func TestSharedACLName(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"default-policy", false},
		{"generic-ssh-management", false},
		{"generic-web-in", false},
		{"random-name", true},
		{"webapp-only", true},
		{"", true},
	}
	for _, tc := range cases {
		err := checkSharedACLName(tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("checkSharedACLName(%q) err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}

func TestHostScopedName(t *testing.T) {
	cases := []struct {
		host, name string
		wantErr    bool
	}{
		{"web1", "web1-backends", false},
		{"web1", "not-web1", true},
		{"web1", "web1x-backends", true},
		{"web1", "web1-", true}, // trailing hyphen fails base rule
	}
	for _, tc := range cases {
		err := checkHostScopedName("acl", tc.host, tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("checkHostScopedName(%q, %q) err=%v, wantErr=%v",
				tc.host, tc.name, err, tc.wantErr)
		}
	}
}

func TestInstanceScopedName(t *testing.T) {
	cases := []struct {
		instance, name string
		wantErr        bool
	}{
		{"jakbrave", "jakbrave-access-gunicorn", false},
		{"jakbrave", "unrelated", true},
		{"jakbrave", "jakbrave", true}, // no suffix
	}
	for _, tc := range cases {
		err := checkInstanceScopedName("acl", tc.instance, tc.name)
		if (err != nil) != tc.wantErr {
			t.Errorf("checkInstanceScopedName(%q, %q) err=%v, wantErr=%v",
				tc.instance, tc.name, err, tc.wantErr)
		}
	}
}
