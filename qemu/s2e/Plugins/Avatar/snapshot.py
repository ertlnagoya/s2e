#!/usr/bin/env python3

import argparse
import struct

class DummyError(RuntimeError):
    pass
    
def get_string(file):
    string_length = struct.unpack(">H", file.read(2))[0]
    return file.read(string_length).decode(encoding = "iso-8859-1")
    
def parse_cpu_section(file, size):
    cpu = {}
    
    cpu["version"] = struct.unpack(">L", file.read(4))[0]
    if cpu["version"] != 6:
        raise RuntimeError("Wrong CPU version")
    arch = struct.unpack(">B", file.read(1))[0]
    if arch == 0x03:
        cpu["architecture"] = "i386"
    elif arch == 0x3e:
        cpu["architecture"] = "x86_64"
    elif arch == 0x28:
        cpu["architecture"] = "arm"
    else:
        assert(False)
    cpu["model"] = get_string(file)
    
    payload_size = size - 4 - 1 - 2 - len(cpu["model"])
    file.read(payload_size)
    
    return cpu
    
def parse_machine_section(file, size):
    machine = {}
    
    machine["version"] = struct.unpack(">L", file.read(4))[0]
    if machine["version"] != 0:
        raise RuntimeError("Unkown machine version")
    machine["name"] = get_string(file)
    endianness = struct.unpack(">B", file.read(1))[0]
    if endianness == 0:
        machine["endianness"] = "little"
    elif endianness == 1:
        machine["endianness"] = "big-be32"
    elif endianness == 2:
        machine["endianness"] = "big-be8"
    else:
        assert(False)
        
    assert(size == 5 + 2 + len(machine["name"]))
    
    return machine
        
    
    
def parse_ram_section(file, size):
    ram = {}
    
    ram["version"] = struct.unpack(">L", file.read(4))[0]
    if ram["version"] != 4:
        raise RuntimeError("Wrong RAM version")
        
    remaining_size = size - 4
    
    ram["ranges"] = []
    while remaining_size > 0:
        memrange = {
            "address": struct.unpack(">Q", file.read(8))[0],
            "size": struct.unpack(">Q", file.read(8))[0],
            "attributes": struct.unpack(">L", file.read(4))[0],
            "name": get_string(file),
        }
        
        remaining_size -= 8 + 8 + 4 + 2 + len(memrange["name"])
        memrange["fileoffset"] = file.tell()
        for i in range(0, memrange["size"], 4096):
            file.read(min(4096,  memrange["size"] - i))
        remaining_size -= memrange["size"]
        
        ram["ranges"].append(memrange)
    return ram
        

def parse_snapshot_file(filename):
    snapshot = {}
    with open(filename, 'rb') as file:
        snapshot["magic"] = struct.unpack(">L", file.read(4))[0]
        if snapshot["magic"] != 0x51533245:
            raise RuntimeError("Wrong file magic")
        snapshot["version"] = struct.unpack(">L", file.read(4))[0]
        if snapshot["version"] != 0x1:
            raise RuntimeError("Wrong file version")

        snapshot["sections"] = []
        try:
            while True:
                section = {}
                section["type"] = struct.unpack(">B", file.read(1))[0]
                if section["type"] == 0: #End of file
                    break
                elif section["type"] == 0xfe: #Start of section
                    section["size"] = struct.unpack(">L", file.read(4))[0]
                    section["id"] = struct.unpack(">L", file.read(4))[0]
                    section["name"] = get_string(file)
                    
                    if section["id"] == 0:
                        section["data"] = parse_cpu_section(file, section["size"] - 11 - len(section["name"]))
                    elif section["id"] == 1:
                        section["data"] = parse_machine_section(file, section["size"] - 11 - len(section["name"]))
                    elif section["id"] == 2:
                        section["data"] = parse_ram_section(file, section["size"] - 11 - len(section["name"]))
                snapshot["sections"].append(section)
                
        except DummyError:
            pass
#        except struct.error:
#            print("Error: file ended prematurely")
#            pass

    return snapshot

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshot", type = str, help = "Snapshot file")
    
    args = parser.parse_args()
    snapshot = parse_snapshot_file(args.snapshot)
    print(snapshot)

if __name__ == "__main__":
    main()