package rbac

import "testing"

func TestProbeDeniedPermissionExcludedFromAllowList(t *testing.T) {
	s := New()
	if err := s.PutRole(Role{ID: "reader", Allow: []string{"doc:read"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRole(Role{ID: "blocked", Deny: []string{"doc:read"}}); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantRole("u", "reader"); err != nil {
		t.Fatal(err)
	}
	if err := s.GrantRole("u", "blocked"); err != nil {
		t.Fatal(err)
	}
	allow, deny := s.EffectivePermissions("u")
	if len(allow) != 0 || len(deny) != 1 || deny[0] != "doc:read" {
		t.Fatalf("allow=%v deny=%v", allow, deny)
	}
}
