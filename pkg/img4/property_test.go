package img4

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"testing"
)

// Helper function to create property data in the format expected by ParsePropertyMap
func createPropertyData(properties map[string]any) ([]byte, error) {
	var entries []asn1.RawValue

	for name, value := range properties {
		// Marshal property value
		var valueBytes []byte
		var tag int
		var err error

		switch v := value.(type) {
		case int:
			valueBytes, err = asn1.Marshal(v)
			tag = asn1.TagInteger
		case int64:
			valueBytes, err = asn1.Marshal(v)
			tag = asn1.TagInteger
		case uint64:
			// Convert uint64 to int64 for ASN.1 marshaling
			valueBytes, err = asn1.Marshal(int64(v))
			tag = asn1.TagInteger
		case bool:
			valueBytes, err = asn1.Marshal(v)
			tag = asn1.TagBoolean
		case string:
			valueBytes, err = asn1.Marshal(v)
			tag = asn1.TagUTF8String
		case []byte:
			valueBytes, err = asn1.Marshal(v)
			tag = asn1.TagOctetString
		default:
			return nil, fmt.Errorf("unsupported property type: %T", v)
		}

		if err != nil {
			return nil, fmt.Errorf("failed to marshal property %s: %v", name, err)
		}

		// Create property structure
		propStruct := struct {
			Name  string
			Value asn1.RawValue
		}{
			Name: name,
			Value: asn1.RawValue{
				Tag:       tag,
				FullBytes: valueBytes, // Use full bytes including header
			},
		}

		propBytes, err := asn1.Marshal(propStruct)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal property %s: %v", name, err)
		}

		// Use generic private tag
		privateTag := 0x1000

		entries = append(entries, asn1.RawValue{
			Class:      3, // private class
			Tag:        privateTag,
			IsCompound: true,
			Bytes:      propBytes,
		})
	}

	// Concatenate all entries directly (no outer SEQUENCE wrapper)
	var result []byte
	for _, entry := range entries {
		entryBytes, err := asn1.Marshal(entry)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal property entry: %v", err)
		}
		result = append(result, entryBytes...)
	}
	return result, nil
}

func TestPropertyParsing(t *testing.T) {
	// Test basic property parsing with valid data
	tests := []struct {
		name          string
		properties    map[string]any
		expectedProps int
	}{
		{
			name: "simple property set",
			properties: map[string]any{
				"TEST": "test",
				"NUMB": 42,
			},
			expectedProps: 2,
		},
		{
			name:          "empty property set",
			properties:    map[string]any{},
			expectedProps: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create property data using helper function
			propertyData, err := createPropertyData(tt.properties)
			if err != nil {
				t.Fatalf("Failed to create property data: %v", err)
			}

			props, err := ParsePropertyMap(propertyData)
			if err != nil {
				t.Fatalf("ParsePropertyMap() error = %v", err)
			}

			if len(props) != tt.expectedProps {
				t.Errorf("Expected %d properties, got %d", tt.expectedProps, len(props))
			}

			// Verify specific properties match input
			for expectedKey, expectedVal := range tt.properties {
				actualVal, ok := props[expectedKey]
				if !ok {
					t.Errorf("Expected property '%s' to be present", expectedKey)
					continue
				}

				switch expected := expectedVal.(type) {
				case string:
					if actual, ok := actualVal.(string); !ok || actual != expected {
						t.Errorf("Property '%s': expected '%s', got %v", expectedKey, expected, actualVal)
					}
				case int:
					if actual, ok := actualVal.(int); !ok || actual != expected {
						t.Errorf("Property '%s': expected %d, got %v", expectedKey, expected, actualVal)
					}
				case bool:
					if actual, ok := actualVal.(bool); !ok || actual != expected {
						t.Errorf("Property '%s': expected %t, got %v", expectedKey, expected, actualVal)
					}
				case []byte:
					if actual, ok := actualVal.([]byte); !ok || !bytes.Equal(actual, expected) {
						t.Errorf("Property '%s': expected %x, got %v", expectedKey, expected, actualVal)
					}
				}
			}
		})
	}

	// Test error cases with invalid data
	errorTests := []struct {
		name        string
		data        []byte
		expectError bool
	}{
		{
			name:        "invalid ASN.1",
			data:        []byte("invalid"),
			expectError: false, // ParsePropertyMap handles gracefully
		},
		{
			name:        "empty data",
			data:        []byte{},
			expectError: false, // Should return empty map
		},
	}

	for _, tt := range errorTests {
		t.Run(tt.name, func(t *testing.T) {
			props, err := ParsePropertyMap(tt.data)
			if (err != nil) != tt.expectError {
				t.Errorf("ParsePropertyMap() error = %v, expectError %v", err, tt.expectError)
			}
			// For graceful handling, should return empty map
			if !tt.expectError && len(props) != 0 {
				t.Errorf("Expected empty properties map for invalid data, got %d properties", len(props))
			}
		})
	}
}

func TestPropertyTypes(t *testing.T) {
	// Test different property value types
	tests := []struct {
		name         string
		properties   map[string]any
		key          string
		expectedType string
		expectedVal  any
	}{
		{
			name:         "string property",
			properties:   map[string]any{"TEXT": "hello!"},
			key:          "TEXT",
			expectedType: "string",
			expectedVal:  "hello!",
		},
		{
			name:         "integer property",
			properties:   map[string]any{"CNTR": 1000},
			key:          "CNTR",
			expectedType: "int",
			expectedVal:  1000,
		},
		{
			name:         "boolean property",
			properties:   map[string]any{"FLAG": true},
			key:          "FLAG",
			expectedType: "bool",
			expectedVal:  true,
		},
		{
			name:         "data property",
			properties:   map[string]any{"DATA": []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}},
			key:          "DATA",
			expectedType: "[]byte",
			expectedVal:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create property data using helper function
			propertyData, err := createPropertyData(tt.properties)
			if err != nil {
				t.Fatalf("Failed to create property data: %v", err)
			}

			props, err := ParsePropertyMap(propertyData)
			if err != nil {
				t.Fatalf("ParsePropertyMap() error = %v", err)
			}

			val, ok := props[tt.key]
			if !ok {
				t.Fatalf("Expected property '%s' to be present", tt.key)
			}

			switch tt.expectedType {
			case "string":
				if str, ok := val.(string); !ok {
					t.Errorf("Expected string type, got %T", val)
				} else if str != tt.expectedVal.(string) {
					t.Errorf("Expected '%s', got '%s'", tt.expectedVal.(string), str)
				}
			case "int":
				if num, ok := val.(int); !ok {
					t.Errorf("Expected int type, got %T", val)
				} else if num != tt.expectedVal.(int) {
					t.Errorf("Expected %d, got %d", tt.expectedVal.(int), num)
				}
			case "bool":
				if b, ok := val.(bool); !ok {
					t.Errorf("Expected bool type, got %T", val)
				} else if b != tt.expectedVal.(bool) {
					t.Errorf("Expected %t, got %t", tt.expectedVal.(bool), b)
				}
			case "[]byte":
				if data, ok := val.([]byte); !ok {
					t.Errorf("Expected []byte type, got %T", val)
				} else if !bytes.Equal(data, tt.expectedVal.([]byte)) {
					t.Errorf("Expected %x, got %x", tt.expectedVal.([]byte), data)
				}
			}
		})
	}
}

func TestPropertyEdgeCases(t *testing.T) {
	// Test edge cases and error conditions
	tests := []struct {
		name        string
		propertyData []byte
		expectError bool
		description string
	}{
		{
			name: "invalid ASN.1 data",
			propertyData: []byte("invalid"),
			expectError: false, // ParsePropertyMap handles this gracefully by returning empty map
			description: "completely invalid ASN.1 data",
		},
		{
			name: "empty data",
			propertyData: []byte{},
			expectError: false, // Empty data should return empty properties map
			description: "empty input data",
		},
		{
			name: "truncated ASN.1 data",
			propertyData: []byte{0x83, 0x10, 0x00}, // Private class tag with truncated data
			expectError: false, // Should handle gracefully
			description: "truncated ASN.1 entry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			props, err := ParsePropertyMap(tt.propertyData)
			if (err != nil) != tt.expectError {
				t.Fatalf("ParsePropertyMap() error = %v, expectError %v (%s)", err, tt.expectError, tt.description)
			}
			if !tt.expectError {
				t.Logf("Parsed %d properties for test: %s", len(props), tt.description)
			}
		})
	}
}

func TestPropertyRoundtrip(t *testing.T) {
	// Test that properties can be created, marshaled, and parsed back correctly
	originalProps := map[string]any{
		"TEXT": "test",
		"NUMB": 100,
		"FLAG": true,
	}

	// Create property data using helper function
	propertyData, err := createPropertyData(originalProps)
	if err != nil {
		t.Fatalf("Failed to create property data: %v", err)
	}

	// Parse the data back
	props, err := ParsePropertyMap(propertyData)
	if err != nil {
		t.Fatalf("ParsePropertyMap() error = %v", err)
	}

	// Verify all expected properties are present and match
	for key, expectedVal := range originalProps {
		val, ok := props[key]
		if !ok {
			t.Errorf("Expected property '%s' to be present", key)
			continue
		}

		switch expectedVal := expectedVal.(type) {
		case string:
			if str, ok := val.(string); !ok || str != expectedVal {
				t.Errorf("Property '%s': expected '%s', got %v", key, expectedVal, val)
			}
		case int:
			if num, ok := val.(int); !ok || num != expectedVal {
				t.Errorf("Property '%s': expected %d, got %v", key, expectedVal, val)
			}
		case bool:
			if b, ok := val.(bool); !ok || b != expectedVal {
				t.Errorf("Property '%s': expected %t, got %v", key, expectedVal, val)
			}
		}
	}
}

func BenchmarkPropertyParsing(b *testing.B) {
	// Create benchmark property data
	benchmarkProps := map[string]any{
		"TEXT": "test",
		"NUMB": 100,
		"DATA": []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		"FLAG": true,
	}

	propertyData, err := createPropertyData(benchmarkProps)
	if err != nil {
		b.Fatalf("Failed to create benchmark property data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParsePropertyMap(propertyData)
	}
}