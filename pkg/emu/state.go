package emu

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type field struct {
	Name  string
	Type  string
	Value any
}

type stack struct {
	Addr       uint64
	DataBase64 string
}

type State struct {
	Args      [][]field
	Stack     stack
	Registers map[string]uint64
}

func ParseState(name string) (*State, error) {
	var state State

	data, err := os.ReadFile(name)
	if err != nil {
		return nil, fmt.Errorf("error reading state file: %v", err)
	}

	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("error unmarshalling state file: %v", err)
	}

	return &state, nil
}

func (state *State) Dump() {
	fmt.Printf("Args: %v\n", state.Args)
	fmt.Printf("Stack: %v\n", state.Stack)
	fmt.Printf("Registers: %v\n", state.Registers)
}

func (state *State) DumpYaml() {
	data, err := yaml.Marshal(state)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", data)
}
