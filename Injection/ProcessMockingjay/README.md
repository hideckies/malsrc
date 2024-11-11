# Process Mockingjay

## Find Vulnerable DLLs

To find DLLs that contain RWX sections, run the following command in the target machine:

```sh
python3 find_vuln_dlls.py <directory_path_to_search>
```

If found, set the DLL path in the `ProcessMockingjay.cpp`.
