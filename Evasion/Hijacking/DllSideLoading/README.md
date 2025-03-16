# Dll Side Loading

## Attack Flow

1. Copy the target executable into an empty directory somewhere (e.g. `C:\Users\<username>\Desktop\Test`) to isolate it from existing DLLs and dependencies.  
2. Run the executable in the empty directory, and check error message.  
3. If an error message such as "Dll Not Found" appears, proceed to analyze further using **Process Monitor (procmon.exe)**. Even if no error is displayed, it's worth checking the executable's behavior for missing DLLs.
4. Open **Process Monitor**, and then add following filters:

    - `Process Name` `is` `example.exe` then `Include` (replace "example.exe" with the target name)
    - `Path` `ends with` `.dll` then `Include`
    - `Result` `is` `NAME NOT FOUND` then `Include`

5. If the results found, see the Paths and find writable directory that we can create our own DLL with the same name.  
6. If a writable directory found, insert our maliciou DLL there. Note that we need to create an exported function with the same name that the target executable imports. We can check it by refering **Import Address Table (IAT)** with reverse engineering tools such as x64dbg, IDA Pro or others.
7. After that, our DLL will be executed when the target executable is executed.

## Usefule Tools

We can find vulnerable EXEs/DLLs using [HijackLibs](https://hijacklibs.net/).

## Resources

- [Exploring DLL Hijacking](https://unit42.paloaltonetworks.com/dll-hijacking-techniques/)