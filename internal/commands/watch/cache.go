package watch

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"

	"github.com/apex/log"
	lru "github.com/hashicorp/golang-lru/v2"
)

type WatchCache interface {
	Add(key string, value any)
	Get(key, value string) (any, bool)
	Has(key, value string) bool
}

type MemoryCache struct {
	cache *lru.Cache[string, any]
}

type FileCache struct {
	path string
}

func NewMemoryCache(size int) (*MemoryCache, error) {
	lcache, err := lru.New[string, any](size)
	if err != nil {
		return nil, err
	}
	return &MemoryCache{
		cache: lcache,
	}, nil
}

func (c *MemoryCache) Add(key string, value any) {
	c.cache.Add(key, value)
}

func (c *MemoryCache) Get(key, value string) (any, bool) {
	val, found := c.cache.Get(key)
	if !found {
		return nil, false
	}
	switch v := val.(type) {
	case []any:
		for _, item := range v {
			if itemStr, ok := item.(string); ok && itemStr == value {
				return item, true
			}
		}
	case map[string]any:
		if vv, ok := v[value]; ok {
			return vv, true
		}
	case string:
		if v == value {
			return v, true
		}
	}
	return nil, false
}
func (c *MemoryCache) Has(key, value string) bool {
	if val, ok := c.cache.Get(key); ok {
		switch v := val.(type) {
		case []any:
			for _, item := range v {
				if itemStr, ok := item.(string); ok && itemStr == value {
					return true
				}
			}
		case map[string]any:
			if vStr, ok := v[value]; ok {
				if strVal, ok := vStr.(string); ok && strVal == value {
					return true
				}
			}
		case string:
			if v == value {
				return true
			}
		}
	}
	return false
}

func NewFileCache(path string) (*FileCache, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	// Check if file exists, create it if it doesn't
	if _, err := os.Stat(path); os.IsNotExist(err) {
		// initialize empty JSON object
		if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
			return nil, err
		}
	}

	return &FileCache{
		path: path,
	}, nil
}

func (c *FileCache) Add(key string, value any) {
	// read existing JSON
	data, err := os.ReadFile(c.path)
	if err != nil {
		panic(err)
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		// on parse error, reset map
		m = make(map[string]any)
	}
	if val, found := m[key]; found {
		// set the latest value
		switch v := val.(type) {
		case []any:
			m[key] = append(v, value)
		case map[string]any:
			maps.Copy(v, value.(map[string]any))
		case string:
			m[key] = value
		}
	} else {
		// if the key doesn't exist, set the value
		m[key] = value
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.WithError(err).Error("failed to marshal cache JSON")
		return
	}
	if err := os.WriteFile(c.path, out, 0644); err != nil {
		log.WithError(err).Error("failed to write cache JSON")
	}
}

func (c *FileCache) Get(key, value string) (any, bool) {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil, false
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, false
	}
	if val, ok := m[key]; ok {
		switch v := val.(type) {
		case []any:
			for _, item := range v {
				if itemStr, ok := item.(string); ok && itemStr == value {
					return item, true
				}
			}
		case map[string]any:
			if vv, ok := v[value]; ok {
				return vv, true
			}
		case string:
			if v == value {
				return v, true
			}
		}
	}
	return nil, false
}

func (c *FileCache) Has(key, value string) bool {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return false
	}
	m := make(map[string]any)
	if err := json.Unmarshal(data, &m); err != nil {
		return false
	}
	if vals, ok := m[key]; ok {
		switch v := vals.(type) {
		case []any:
			for _, item := range v {
				if itemStr, ok := item.(string); ok && itemStr == value {
					return true
				}
			}
		case map[string]any:
			if vStr, ok := v[value]; ok {
				if strVal, ok := vStr.(string); ok && strVal == value {
					return true
				}
			}
		case string:
			if v == value {
				return true
			}
		}
	}
	return false
}
