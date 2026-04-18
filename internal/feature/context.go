package feature

import "context"

// tenantCtxKey is the unexported type used as the context key for the
// per-request tenant snapshot. Using a custom type avoids collisions with
// keys defined in other packages.
type tenantCtxKey struct{}

// WithTenant returns a derived context carrying the supplied tenant
// snapshot. Passing a nil tenant is valid and results in a context that
// reports no tenant via TenantFromContext.
func WithTenant(ctx context.Context, tenant *TenantSnapshot) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, tenant)
}

// TenantFromContext returns the tenant snapshot previously attached with
// WithTenant, or nil if no tenant has been set on ctx.
func TenantFromContext(ctx context.Context) *TenantSnapshot {
	if ctx == nil {
		return nil
	}
	v, _ := ctx.Value(tenantCtxKey{}).(*TenantSnapshot)
	return v
}
