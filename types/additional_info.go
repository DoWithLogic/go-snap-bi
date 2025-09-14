package types

// AdditionalInfo represents additional key-value data for API requests/responses.
// It provides type-safe methods for common operations.
type AdditionalInfo map[string]any

// NewAdditionalInfo creates a new empty AdditionalInfo map.
func NewAdditionalInfo() AdditionalInfo {
	return make(AdditionalInfo)
}

// Set adds or updates a key-value pair in the AdditionalInfo map.
// Key must be a string, value can be any type.
func (ai AdditionalInfo) Set(key string, value any) AdditionalInfo {
	ai[key] = value
	return ai
}

// Get retrieves a value by key. Returns the value and whether the key exists.
func (ai AdditionalInfo) Get(key string) (any, bool) {
	value, exists := ai[key]
	return value, exists
}

// GetString retrieves a string value by key. Returns empty string if not found or not a string.
func (ai AdditionalInfo) GetString(key string) string {
	if value, exists := ai[key]; exists {
		if str, ok := value.(string); ok {
			return str
		}
	}
	return ""
}

// GetInt retrieves an integer value by key. Returns 0 if not found or not an integer.
func (ai AdditionalInfo) GetInt(key string) int {
	if value, exists := ai[key]; exists {
		switch v := value.(type) {
		case int:
			return v
		case float64: // JSON numbers unmarshal as float64
			return int(v)
		case int64:
			return int(v)
		case int32:
			return int(v)
		}
	}
	return 0
}

// GetFloat64 retrieves a float64 value by key. Returns 0 if not found or not a float64.
func (ai AdditionalInfo) GetFloat64(key string) float64 {
	if value, exists := ai[key]; exists {
		if f, ok := value.(float64); ok {
			return f
		}
	}
	return 0
}

// GetBool retrieves a boolean value by key. Returns false if not found or not a boolean.
func (ai AdditionalInfo) GetBool(key string) bool {
	if value, exists := ai[key]; exists {
		if b, ok := value.(bool); ok {
			return b
		}
	}
	return false
}

// Delete removes a key-value pair from the AdditionalInfo map.
func (ai AdditionalInfo) Delete(key string) {
	delete(ai, key)
}

// Exists checks if a key exists in the AdditionalInfo map.
func (ai AdditionalInfo) Exists(key string) bool {
	_, exists := ai[key]
	return exists
}

// Merge combines another AdditionalInfo map into the current one.
// Existing keys will be overwritten by the source map.
func (ai AdditionalInfo) Merge(source AdditionalInfo) AdditionalInfo {
	for key, value := range source {
		ai[key] = value
	}
	return ai
}

// Clone creates a deep copy of the AdditionalInfo map.
func (ai AdditionalInfo) Clone() AdditionalInfo {
	clone := make(AdditionalInfo)
	for key, value := range ai {
		clone[key] = value
	}
	return clone
}

// Keys returns all keys in the AdditionalInfo map.
func (ai AdditionalInfo) Keys() []string {
	keys := make([]string, 0, len(ai))
	for key := range ai {
		keys = append(keys, key)
	}
	return keys
}

// Len returns the number of key-value pairs in the AdditionalInfo map.
func (ai AdditionalInfo) Len() int {
	return len(ai)
}

// IsEmpty checks if the AdditionalInfo map is empty.
func (ai AdditionalInfo) IsEmpty() bool {
	return len(ai) == 0
}

// Clear removes all key-value pairs from the AdditionalInfo map.
func (ai AdditionalInfo) Clear() {
	for key := range ai {
		delete(ai, key)
	}
}

// ToMap returns the underlying map for interoperability.
func (ai AdditionalInfo) ToMap() map[string]interface{} {
	return map[string]interface{}(ai)
}
