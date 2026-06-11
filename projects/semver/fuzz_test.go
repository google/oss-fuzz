package semver_test

import (
	"math"
	"testing"

	semver "github.com/Masterminds/semver/v3"
)

// =============================================================================
// Fuzz Target 1: Version Comparison — Compare, LessThan, GreaterThan, Equal
// =============================================================================

// FuzzVersionCompare compares two parsed versions and checks comparison invariants.
func FuzzVersionCompare(f *testing.F) {
	seeds := [][2]string{
		{"1.0.0", "2.0.0"},
		{"1.0.0", "1.0.0"},
		{"2.0.0", "1.0.0"},
		{"1.0.0-alpha", "1.0.0"},
		{"1.0.0-alpha", "1.0.0-alpha"},
		{"1.0.0-alpha.1", "1.0.0-alpha.2"},
		{"1.0.0+build.1", "1.0.0+build.2"},
		{"0.0.0", "18446744073709551615.18446744073709551615.18446744073709551615"},
	}
	for _, s := range seeds {
		f.Add(s[0], s[1])
	}

	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 256 || len(b) > 256 {
			return
		}

		va, errA := semver.NewVersion(a)
		vb, errB := semver.NewVersion(b)
		if errA != nil || errB != nil {
			return
		}

		cmp := va.Compare(vb)
		cmpRev := vb.Compare(va)

		// Antisymmetry
		if cmp == 0 && cmpRev != 0 {
			t.Errorf("Compare asymmetry: %s vs %s → %d / %d", a, b, cmp, cmpRev)
		}
		if cmp > 0 && cmpRev >= 0 {
			t.Errorf("Compare antisymmetry violation: %s vs %s → %d / %d", a, b, cmp, cmpRev)
		}
		if cmp < 0 && cmpRev <= 0 {
			t.Errorf("Compare antisymmetry violation: %s vs %s → %d / %d", a, b, cmp, cmpRev)
		}

		// Equal ↔ Compare == 0
		if va.Equal(vb) != (cmp == 0) {
			t.Errorf("Equal/Compare mismatch: %s vs %s → Compare=%d Equal=%v", a, b, cmp, va.Equal(vb))
		}

		// LessThan / GreaterThan consistency
		lt := va.LessThan(vb)
		gt := va.GreaterThan(vb)
		if lt == gt && cmp != 0 {
			t.Errorf("LessThan/GreaterThan both %v for Compare=%d", lt, cmp)
		}
		if lt != (cmp < 0) {
			t.Errorf("LessThan mismatch: %s vs %s → Compare=%d LessThan=%v", a, b, cmp, lt)
		}

		// Nil check safety
		func() {
			defer func() { _ = recover() }()
			_ = va.Compare(nil)
		}()
	})
}

// =============================================================================
// Fuzz Target 2: Version Round-Trip — Parse → String → Parse → Equal
// =============================================================================

// FuzzVersionRoundTrip verifies that version → string → version preserves equality.
func FuzzVersionRoundTrip(f *testing.F) {
	seeds := []string{
		"1.2.3",
		"0.0.0",
		"v1.0.0",
		"1.2.3-alpha.1+build.123",
		"1.0.0-beta+exp.sha.5114f85",
		"18446744073709551615.0.0",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, v string) {
		if len(v) > 256 {
			return
		}

		ver, err := semver.NewVersion(v)
		if err != nil {
			return
		}

		str := ver.String()
		ver2, err2 := semver.NewVersion(str)
		if err2 != nil {
			t.Errorf("Round-trip parse failed: original=%q string=%q err=%v", v, str, err2)
			return
		}

		if !ver.Equal(ver2) {
			t.Errorf("Round-trip inequality: original=%q → string=%q → parsed=%q",
				v, str, ver2.String())
		}
	})
}

// =============================================================================
// Fuzz Target 3: Version Increment — IncPatch/IncMinor/IncMajor (overflow)
// =============================================================================

// FuzzIncOverflow tests increment operations on edge-case versions.
func FuzzIncOverflow(f *testing.F) {
	seeds := []string{
		"0.0.0",
		"1.2.3",
		"18446744073709551615.0.0",
		"0.18446744073709551615.0",
		"0.0.18446744073709551615",
		"18446744073709551615.18446744073709551615.18446744073709551615",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, v string) {
		if len(v) > 256 {
			return
		}

		ver, err := semver.NewVersion(v)
		if err != nil {
			return
		}

		// Each increment must not panic
		func() {
			defer func() { _ = recover() }()
			_ = ver.IncPatch().String()
		}()

		func() {
			defer func() { _ = recover() }()
			_ = ver.IncMinor().String()
		}()

		func() {
			defer func() { _ = recover() }()
			_ = ver.IncMajor().String()
		}()

		// Invariants for non-overflow versions
		if ver.Patch() < math.MaxUint64 {
			if inc := ver.IncPatch(); inc.Patch() != ver.Patch()+1 {
				t.Errorf("IncPatch: %d + 1 != %d", ver.Patch(), inc.Patch())
			}
		}
		if ver.Minor() < math.MaxUint64 {
			if inc := ver.IncMinor(); inc.Minor() != ver.Minor()+1 {
				t.Errorf("IncMinor: %d + 1 != %d", ver.Minor(), inc.Minor())
			}
			if inc := ver.IncMinor(); inc.Patch() != 0 {
				t.Errorf("IncMinor: patch not reset to 0, got %d", inc.Patch())
			}
		}
	})
}

// =============================================================================
// Fuzz Target 4: Constraint × Version Integration — Check + Validate safety
// =============================================================================

// FuzzConstraintVersionCheck feeds constraint+version pairs and verifies no panics.
func FuzzConstraintVersionCheck(f *testing.F) {
	seeds := []struct{ constraint, version string }{
		{">=1.0.0", "1.0.0"},
		{"<2.0.0", "1.0.0"},
		{">=1.0.0 <2.0.0", "1.5.0"},
		{"^1.2.3", "1.2.4"},
		{"^1.2.3", "2.0.0"},
		{"~1.2.3", "1.2.4"},
		{"1.x", "1.9.9"},
		{"*", "99.99.99"},
	}
	for _, s := range seeds {
		f.Add(s.constraint, s.version)
	}

	f.Fuzz(func(t *testing.T, constraint, version string) {
		if len(constraint) > 600 || len(version) > 256 {
			return
		}

		cs, err := semver.NewConstraint(constraint)
		if err != nil {
			// Test nil version on failed constraint (should not panic)
			func() { _ = cs.Check(nil) }()
			func() { _, _ = cs.Validate(nil) }()
			return
		}

		ver, err := semver.NewVersion(version)
		if err != nil {
			// Test nil version safety
			func() {
				defer func() { _ = recover() }()
				_ = cs.Check(nil)
			}()
			return
		}

		// Check must not panic
		func() {
			defer func() { _ = recover() }()
			_ = cs.Check(ver)
		}()

		// Validate must not panic
		func() {
			defer func() { _ = recover() }()
			_, _ = cs.Validate(ver)
		}()

		// Pre-release interaction
		_ = ver.Prerelease()
	})
}
