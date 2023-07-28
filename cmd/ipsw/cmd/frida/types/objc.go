package types

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
)

var colorBold = color.New(color.Bold).SprintFunc()
var colorHeader = color.New(color.FgHiBlue).SprintFunc()
var ColorFaint = color.New(color.Faint, color.FgHiBlue).SprintFunc()

type Argument struct {
	TypeString        string `json:"typeString,omitempty"`
	TypeDescription   string `json:"typeDescription,omitempty"`
	Object            string `json:"object,omitempty"`
	ObjectDescription string `json:"objectDescription,omitempty"`
}

func (a Argument) String() string {
	return fmt.Sprintf("\t\t%s (%s)", colorBold(a.TypeDescription), ColorFaint(a.ObjectDescription))
}

type Payload struct {
	TargetType         string     `json:"targetType,omitempty"`
	TargetClass        string     `json:"targetClass,omitempty"`
	TargetMethod       string     `json:"targetMethod,omitempty"`
	Args               []Argument `json:"args,omitempty"`
	ReturnType         string     `json:"returnType,omitempty"`
	RetTypeDescription string     `json:"retTypeDescription,omitempty"`
	ReturnDescription  string     `json:"returnDescription,omitempty"`
	Backtrace          string     `json:"backtrace,omitempty"`
}

func (p Payload) String() string {
	var args []string
	for _, arg := range p.Args {
		args = append(args, arg.String())
	}
	return fmt.Sprintf("\t%s %s(\n%s\n\t) -> %s (%s)", colorBold(p.TargetType), colorHeader(p.TargetClass), strings.Join(args, ",\n"), colorBold(p.RetTypeDescription), ColorFaint(p.ReturnDescription))
}
