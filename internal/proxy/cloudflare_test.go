package proxy

import (
	"net"
	"testing"
)

func TestCFValidator_KnownRange(t *testing.T) {
	v := &CFValidator{enabled: true}
	_, cidr, _ := net.ParseCIDR("173.245.48.0/20")
	v.nets = []*net.IPNet{cidr}

	if !v.IsCloudflareIP("173.245.48.1") {
		t.Error("should accept CF IP")
	}
	if v.IsCloudflareIP("1.2.3.4") {
		t.Error("should reject non-CF IP")
	}
}

func TestCFValidator_Disabled(t *testing.T) {
	v := &CFValidator{enabled: false}
	if !v.IsCloudflareIP("1.2.3.4") {
		t.Error("disabled validator should accept all")
	}
}
