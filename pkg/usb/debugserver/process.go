package debugserver

import (
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type EventOutput struct {
	output []byte
}

type EventThread struct{}

type Process struct {
	c        *Client
	stdoutR  *io.PipeReader
	stdoutW  *io.PipeWriter
	interupt chan struct{}
	name     string
	args     []string
	env      []string
}

func makeArgs(args []string) string {
	var ret []string
	for i, arg := range args {
		encoded := hex.EncodeToString([]byte(arg))
		ret = append(ret,
			strconv.Itoa(len(encoded)),
			strconv.Itoa(i),
			encoded)
	}
	return "A" + strings.Join(ret, ",")
}

func NewProcess(udid string, args, env []string) (*Process, error) {
	client, err := NewClient(udid)
	if err != nil {
		return nil, err
	}

	stdoutR, stdoutW := io.Pipe()
	p := &Process{
		c:        client,
		interupt: make(chan struct{}, 1),
		stdoutR:  stdoutR,
		stdoutW:  stdoutW,
		args:     args,
		env:      env,
	}

	return p, nil
}

func (p *Process) Args() []string {
	return p.args
}

func (p *Process) Stdout() io.Reader {
	return p.stdoutR
}

func (p *Process) continueLoop() error {
	for {
		pck, err := p.c.Recv()
		if err != nil {
			return err
		}
		if pck == "" {
			continue
		}
		switch pck[0] {
		case 'O':
			data, err := hex.DecodeString(pck[1:])
			if err != nil {
				return err
			}
			p.stdoutW.Write(data)
		case 'T':
			p.interupt <- struct{}{}
			return nil
		default:
			return fmt.Errorf("unkown packet: %s", pck)
		}
	}
}

func (p *Process) requests(commands ...string) error {
	for _, cmd := range commands {
		if _, err := p.c.Request(cmd); err != nil {
			return err
		}
	}
	return nil
}

func (p *Process) Start() error {
	seq := []string{
		makeArgs(p.Args()),
	}
	for _, e := range p.env {
		seq = append(seq, "QEnvironmentHexEncoded:"+hex.EncodeToString([]byte(e)))
	}
	seq = append(seq, "qLaunchSuccess")

	if err := p.start(seq...); err != nil {
		return err
	}
	return p.Continue()
}

func (p *Process) Continue() error {
	go p.continueLoop()
	return p.c.Send("c")
}

func (p *Process) Interrupt() error {
	if _, err := p.c.Conn().Write([]byte{'\003'}); err != nil {
		return err
	}
	<-p.interupt
	return nil
}

func (p *Process) Kill() error {
	if err := p.Interrupt(); err != nil {
		return err
	}
	if _, err := p.c.Request("k"); err != nil {
		return err
	}
	return p.stdoutW.Close()
}

func (p *Process) bootstrap() error {
	return p.requests(
		"QStartNoAckMode",
		"QEnableErrorStrings",
		"QSetDetachOnError:1",
		"QSetDisableASLR:1",
		"qProcessInfo",
	)
}

func (p *Process) start(commands ...string) error {
	if err := p.bootstrap(); err != nil {
		return err
	}

	for _, cmd := range commands {
		if _, err := p.c.Request(cmd); err != nil {
			return err
		}
	}

	return nil
}

func (p *Process) WaitByName(name string) error {
	if err := p.start(
		"vAttachWait;" + hex.EncodeToString([]byte(name)),
	); err != nil {
		return err
	}
	return p.Continue()
}
