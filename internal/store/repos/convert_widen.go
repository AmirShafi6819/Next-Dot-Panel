package repos

// i64ToI32 narrows an optional int64 metric into the optional int32 that the
// domain uses for process counts. Nil-safe: an absent metric stays absent,
// never becomes zero.
func i64ToI32(p *int64) *int32 {
	if p == nil {
		return nil
	}
	v := int32(*p)
	return &v
}

// i32ToI64 widens an optional int32 back to int64 for the sqlite-generated
// metric params, which use *int64 while postgres uses *int32. Nil-safe.
func i32ToI64(p *int32) *int64 {
	if p == nil {
		return nil
	}
	v := int64(*p)
	return &v
}
