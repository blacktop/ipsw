package watch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	lru "github.com/hashicorp/golang-lru/v2"
)

type Tags []string

type Commit string

type Function map[string]string

type CacheItem struct {
	Tags      Tags     `json:"tags,omitempty"`
	Commit    Commit   `json:"commit,omitempty"`
	Functions Function `json:"functions,omitempty"`
	URL       string   `json:"url,omitempty"`
}

type Cache map[string]CacheItem

type WatchCache interface {
	Add(key string, value any) error
	Get(key string) *CacheItem
	Has(key string, value any) bool
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

func (c *MemoryCache) Add(key string, value any) error {
	c.cache.Add(key, value)
	return nil
}
func (c *MemoryCache) Get(key string) *CacheItem {
	val, found := c.cache.Get(key)
	if !found {
		return nil
	}
	item := val.(CacheItem)
	return &item
}
func (c *MemoryCache) Has(key string, value any) bool {
	if item, ok := c.cache.Get(key); ok {
		switch v := value.(type) {
		case Tags:
			for _, tag := range v {
				if slices.Contains(item.(CacheItem).Tags, tag) {
					return true
				}
			}
		case Commit:
			return item.(CacheItem).Commit == v
		case Function:
			for name, commit := range v {
				if commitVal, ok := item.(CacheItem).Functions[name]; ok && commitVal == commit {
					return true
				}
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
		cache := Cache{}
		var out bytes.Buffer
		if err := json.NewEncoder(&out).Encode(cache); err != nil {
			return nil, fmt.Errorf("failed to encode initial cache data: %w", err)
		}
		if err := os.WriteFile(path, out.Bytes(), 0644); err != nil {
			return nil, err
		}
	}
	return &FileCache{
		path: path,
	}, nil
}

func (c *FileCache) Add(key string, value any) error {
	// read existing JSON
	data, err := os.ReadFile(c.path)
	if err != nil {
		return fmt.Errorf("failed to read cache file %s: %w", c.path, err)
	}
	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return fmt.Errorf("failed to unmarshal cache file %s: %w", c.path, err)
	}
	if item, found := cache[key]; found {
		switch v := value.(type) {
		case Tags:
			// Merge tags with existing ones
			for _, tag := range v {
				if !slices.Contains(item.Tags, tag) {
					item.Tags = append(item.Tags, tag)
				}
			}
		case Commit:
			// Update commit if it is not empty
			if v != "" {
				item.Commit = v
			}
		case Function:
			maps.Copy(item.Functions, v)
		default:
			return fmt.Errorf("unexpected cache item type %T", v)
		}
		cache[key] = item
	} else {
		switch v := value.(type) {
		case Tags:
			cache[key] = CacheItem{Tags: v}
		case Commit:
			cache[key] = CacheItem{Commit: v}
		case Function:
			cache[key] = CacheItem{Functions: v}
		default:
			return fmt.Errorf("unexpected cache item type %T", v)
		}
	}
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(cache); err != nil {
		return fmt.Errorf("failed to encode cache to JSON: %w", err)
	}
	if err := os.WriteFile(c.path, out.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write cache JSON: %w", err)
	}

	return nil
}

func (c *FileCache) Get(key string) *CacheItem {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return nil
	}
	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil
	}
	if item, ok := cache[key]; ok {
		return &item
	}
	return nil
}

func (c *FileCache) Has(key string, value any) bool {
	data, err := os.ReadFile(c.path)
	if err != nil {
		return false
	}
	var cache Cache
	if err := json.Unmarshal(data, &cache); err != nil {
		return false
	}
	if item, ok := cache[key]; ok {
		switch v := value.(type) {
		case Tags:
			for _, tag := range v {
				if slices.Contains(item.Tags, tag) {
					return true
				}
			}
		case Commit:
			return item.Commit == v
		case Function:
			for name, commit := range v {
				if commitVal, ok := item.Functions[name]; ok && commitVal == commit {
					return true
				}
			}
		}
	}
	return false
}
