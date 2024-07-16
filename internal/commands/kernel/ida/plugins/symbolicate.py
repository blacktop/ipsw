import idaapi
import idautils
import idc
import json
import os


class SymbolicatePlugin(idaapi.plugin_t):
    flags = 0
    comment = "Symbolicate Plugin"
    help = "This plugin prompts the user for a symbol map JSON file and processes it."
    wanted_name = "'ipsw' Symbolicate Plugin"
    wanted_hotkey = "Alt-F8"

    def init(self):
        print("Symbolicate Plugin initialized.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        file_path = idaapi.ask_file(0, "*.json", "Select a symbol map JSON file")
        if file_path:
            try:
                with open(file_path, "r") as file:
                    data = json.load(file)
                    self.process_symbol_map(data)
            except Exception as e:
                print(f"Failed to load symbol map JSON file: {e}")
        else:
            print("No file selected.")

    def process_symbol_map(self, data):
        # Process the symbol map JSON data
        addr2sym = json.dumps(data, indent=4)
        for addr, sym in data.items():
            print(f"[Symbolicated] Address: {addr}, Symbol: {sym}")
            idc.set_name(int(addr, 10), sym, idc.SN_NOWARN)

    def term(self):
        pass
        # print("Symbolicate Plugin terminated.")


def PLUGIN_ENTRY():
    return SymbolicatePlugin()
