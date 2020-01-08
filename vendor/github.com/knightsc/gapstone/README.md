gapstone
====

Gapstone is a Go binding for the Capstone disassembly library.

## CURRENT UPSTREAM VERSION: 4.0.1
[![Build Status](https://travis-ci.org/knightsc/gapstone.svg?branch=master)](https://travis-ci.org/knightsc/gapstone)

next branch at:
```
commit aaffb38c44fa58f510ba9b6264f7079bfbba4c8e
Author: Richard Henderson <rth@twiddle.net>
Date:   Mon Dec 23 02:30:58 2019 -1000

    Constify backends (#1549)
```

SUMMARY
===

( FROM THE CAPSTONE README )

Capstone is a disassembly framework with the target of becoming the ultimate
disasm engine for binary analysis and reversing in the security community.

Created by Nguyen Anh Quynh, then developed and maintained by a small community,
Capstone offers some unparalleled features:

- Support multiple hardware architectures: ARM, ARM64 (ARMv8), Mips, PPC, Sparc,
  SystemZ, XCore and X86.

- Having clean/simple/lightweight/intuitive architecture-neutral API.

- Provide details on disassembled instruction (called “decomposer” by others).

- Provide semantics of the disassembled instruction, such as list of implicit
  registers read & written.

- Implemented in pure C language, with lightweight wrappers for C++, C#, Go,
  Java, NodeJS, Ocaml, Python, Ruby & Vala ready (available in main code,
  or provided externally by the community).

- Native support for all popular platforms: Windows, Mac OSX, iOS, Android,
  Linux, *BSD, Solaris, etc.

- Thread-safe by design.

- Special support for embedding into firmware or OS kernel.

- Distributed under the open source BSD license.

Further information is available at http://www.capstone-engine.org

To install:
----

First install the capstone library from either https://github.com/aquynh/capstone
or http://www.capstone-engine.org

Then, assuming you have set up your Go environment according to the docs, just:
```bash
go get -u github.com/knightsc/gapstone
```

Tests are provided. You should probably run them.
```
cd $GOPATH/src/github.com/knightsc/gapstone
go test
```

To start writing code:
----

Take a look at the examples *_test.go

Here's "Hello World":
```go
package main

import (
    "github.com/knightsc/gapstone"
    "log"
)

func main() {

    engine, err := gapstone.New(
        gapstone.CS_ARCH_X86,
        gapstone.CS_MODE_32,
    )

    if err == nil {

        defer engine.Close()

        maj, min := engine.Version()
        log.Printf("Hello Capstone! Version: %v.%v\n", maj, min)

        var x86Code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34" +
            "\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91" +
            "\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00" +
            "\x8d\x87\x89\x67\x00\x00\xb4\xc6"

        insns, err := engine.Disasm(
            []byte(x86Code32), // code buffer
            0x10000,           // starting address
            0,                 // insns to disassemble, 0 for all
        )

        if err == nil {
            log.Printf("Disasm:\n")
            for _, insn := range insns {
                log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
            }
            return
        }
        log.Fatalf("Disassembly error: %v", err)
    }
    log.Fatalf("Failed to initialize engine: %v", err)
}
```

Autodoc is available at http://godoc.org/github.com/knightsc/gapstone

Contributing
----

If you feel like chipping in, especially with better tests or examples, fork and send me a pull req.
