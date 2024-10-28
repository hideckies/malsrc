# Resources:
#   - https://github.com/rapid7/metasploit-framework/blob/master/external/source/shellcode/windows/x86/src/hash.py
# 
# Usage:
#   python3 hash.py kernel32.dll WinExec

import argparse


def ror(dword: int, bits: int) -> int:
    return (dword >> bits | dword << (32 - bits)) & 0xFFFFFFFF


def unicode(string: str, uppercase: bool = True) -> str:
    result = ''
    if uppercase:
        string = string.upper()
    for c in string:
        result += c + '\x00'
    return result


def hash(module: str, function: str, bits: int = 13, print_hash: bool = True) -> str:
    module_hash = 0
    function_hash = 0
    for c in unicode(module + '\x00'):
        module_hash = ror(module_hash, bits)
        module_hash += ord(c)
    for c in str(function + '\x00'):
        function_hash = ror(function_hash, bits)
        function_hash += ord(c)
    h = module_hash + function_hash & 0xFFFFFFFF
    if print_hash:
        print('[+] 0x%08X = %s!%s' % (h, module.lower(), function))
    return h


def main(argv=None):
    parser = argparse.ArgumentParser(description="Calculates hash for modules and functions.")
    parser.add_argument("module", type=str, help="Module name")
    parser.add_argument("function", type=str, help="Function name")

    args = parser.parse_args()

    mod_name = args.module
    func_name = args.function

    hash(mod_name, func_name)


if __name__ == '__main__':
    main()