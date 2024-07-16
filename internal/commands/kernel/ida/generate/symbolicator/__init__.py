import json
from typing import List
from io import TextIOWrapper


class Version(object):
    def __init__(self, max: str, min: str):
        self.max = max
        self.min = min

    def to_dict(self):
        return {"max": self.max, "min": self.min}

    def write(self, f: TextIOWrapper):
        try:
            f.write("version {\n")
            f.write(f'    max = "{self.max}"\n')
            f.write(f'    min = "{self.min}"\n')
            f.write("}\n\n")
        except Exception as e:
            print(f"Error: failed to write Version {e}")


class Anchor(object):
    def __init__(self, string: str, segment: str, section: str, caller: str):
        self.string = string
        self.segment = segment
        self.section = section
        self.caller = caller

    def to_dict(self):
        return {"string": self.string, "segment": self.segment, "section": self.section, "caller": self.caller}

    def write(self, f: TextIOWrapper):
        try:
            f.write("            new {\n")
            f.write(f"                string = {self.string}\n")
            f.write(f'                segment = "{self.segment}"\n')
            f.write(f'                section = "{self.section}"\n')
            f.write(f'                caller = "{self.caller if self.caller else ""}"\n')
            f.write("            }\n")
        except Exception as e:
            print(f"Error: failed to write Anchor for {self.string} {e}")


class Signature(object):
    def __init__(self, args: int, anchors: List[Anchor], symbol: str, prototype: str, caller: str):
        self.args = args
        self.anchors = anchors
        self.symbol = symbol
        self.prototype = prototype
        self.caller = caller

    def to_dict(self):
        return {
            "args": self.args,
            "anchors": [anchor.to_dict() for anchor in self.anchors],
            "symbol": self.symbol,
            "prototype": self.prototype,
            "caller": self.caller,
        }

    def write(self, f: TextIOWrapper):
        try:
            f.write("    new {\n")
            f.write(f"        args = {self.args}\n")
            f.write("        anchors {\n")
            for anchor in self.anchors:
                anchor.write(f)
            f.write("        }\n")
            f.write(f'        symbol = "{self.symbol}"\n')
            f.write(f'        prototype = ""\n')
            f.write(f'        caller = "{self.caller if self.caller else ""}"\n')
            f.write("    }\n")
        except Exception as e:
            print(f"Error: failed to write Signature for {self.symbol} {e}")


class Symbolicator(object):
    def __init__(self, target: str, total: int, version: Version, signatures: List[Signature]):
        self.target = target
        self.total = total
        self.version = version
        self.signatures = signatures

    def to_dict(self):
        return {
            "target": self.target,
            "total": self.total,
            "version": self.version.to_dict(),
            "signatures": [signature.to_dict() for signature in self.signatures],
        }

    def write_to_json(self, file_path: str):
        with open(file_path, "w") as file:
            json.dump(self.to_dict(), file, indent=4)

    def write_to_pkl(self, filepath: str):
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write('amends "../pkl/Symbolicator.pkl"\n')
                f.write(
                    """
// MIT License
//
// Copyright (c) 2024 blacktop
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE."""
                )
                f.write(f'\n\ntarget = "{self.target}"\n\n')
                f.write(f"total = {self.total}\n\n")
                self.version.write(f)
                f.write("signatures {\n")
                for sig in self.signatures:
                    sig.write(f)
                f.write("}")
        except FileNotFoundError:
            print(f"Error: The file '{filepath}' does not exist.")
        except IOError:
            print(f"Error: An IOError occurred while trying to read '{filepath}'.")
        except Exception as e:
            print(f"Error: failed to write Symbolicator {e}")
