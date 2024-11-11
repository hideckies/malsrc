# 
# Resources:
#   - https://github.com/caueb/Mockingjay/blob/main/rwx_finder.py
# 
import os
import sys
import pefile

def is_rwx_characteristics(characteristics):
    return (
        characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] and
        characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'] and
        characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']
    )

def find_rwx_sections(file_path):
    pe = pefile.PE(file_path)

    rwe_sections = []
    for section in pe.sections:
        if is_rwx_characteristics(section.Characteristics):
            rwe_sections.append(section.Name.decode().rstrip('\x00'))

    return rwe_sections

def scan_directory(directory_path):
    print("[i] Searching...")
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            if file_name.lower().endswith(".dll"):  # Check if the file has .dll extension
                file_path = os.path.join(root, file_name)

                try:
                    #print("File:", file_path)
                    rwe_sections = find_rwx_sections(file_path)
                    if rwe_sections:
                        print("\033[1;32m[i] Found RWX Sections in", file_path, "\033[0m")
                        for section in rwe_sections:
                            print("[i] Section:", section)
                        print()
                except pefile.PEFormatError:
                    pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"[i] Usage: python {sys.argv[0]} directory_path")
    else:
        directory_path = sys.argv[1]
        scan_directory(directory_path)
        print("[i] Scan Finished!")
