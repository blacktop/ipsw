package api

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type contractSchema struct {
	Ref        string                    `json:"$ref"`
	Type       string                    `json:"type"`
	Properties map[string]contractSchema `json:"properties"`
}

func TestSwaggerDeviceAndMountContract(t *testing.T) {
	data, err := os.ReadFile("swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	public, err := os.ReadFile("../www/static/api/swagger.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, public) {
		t.Error("published Swagger schema differs from api/swagger.json")
	}
	var spec struct {
		Paths map[string]map[string]struct {
			Parameters []struct {
				Name   string         `json:"name"`
				In     string         `json:"in"`
				Type   string         `json:"type"`
				Schema contractSchema `json:"schema"`
			} `json:"parameters"`
		} `json:"paths"`
		Responses map[string]struct {
			Schema contractSchema `json:"schema"`
		} `json:"responses"`
		Definitions map[string]contractSchema `json:"definitions"`
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	for path, method := range map[string]string{"/mount/{type}": "post", "/ipsw/fs/ents": "get"} {
		found := false
		for _, param := range spec.Paths[path][method].Parameters {
			if param.Name == "device" && param.In == "query" && param.Type == "string" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s lacks a string device query parameter", path)
		}
	}
	mountSchema := spec.Responses["mountReponse"].Schema
	if mountSchema.Ref != "" {
		mountSchema = spec.Definitions[strings.TrimPrefix(mountSchema.Ref, "#/definitions/")]
	}
	for _, property := range []string{"mount_point", "dmg_path", "retain_dmg", "owns_directory", "already_mounted"} {
		wantType := "string"
		if property == "retain_dmg" || property == "owns_directory" || property == "already_mounted" {
			wantType = "boolean"
		}
		if mountSchema.Properties[property].Type != wantType {
			t.Errorf("mount response JSON body lacks %s property %q", wantType, property)
		}
		found := false
		for _, param := range spec.Paths["/unmount"]["post"].Parameters {
			if param.In == "body" && param.Schema.Properties[property].Type == wantType {
				found = true
			}
		}
		if !found {
			t.Errorf("unmount request body lacks %s property %q", wantType, property)
		}
	}
}
