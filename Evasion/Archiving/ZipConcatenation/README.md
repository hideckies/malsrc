# Zip Concatenation

## How It Works

First of all, create a concatenated ZIP file as below:

```sh
# 1. Create example files to archive.
echo "my first file" > first.txt
echo "my second file" > second.txt

# 2. Zip each file.
zip pt1.zip first.txt
zip pt2.zip second.txt

# 3. Concatenate two zip files.
cat pt1.zip pt2.zip > combined.zip
```

When we try to display the `combined.zip` with the following ZIP readers/handlers, it's displayed in varied way.

- **7zip File Manager**

    The first ZIP file is only revealed.

- **WinRAR**

    The second ZIP file is only revealed.

- **Windows File Explorer**

    The `combined.zip` cannot be extracted.

See resources for more details.

## (Optional) How to Extract

By the way, this combined ZIP file can be extracted with the following method.  
At first, display the ZIP information with `zipinfo` command to see the number of bytes to split:

```sh
zipinfo combined.zip

# Output
Archive:  combined.zip
Zip file size: 367 bytes, number of entries: 1
warning [combined.zip]:  182 extra bytes at beginning or within zipfile
  (attempting to process anyway)
-rw-r--r--  3.0 unx       15 tx stor 24-Nov-13 23:52 second.txt
```

We can see `182` extra bytes in the above output, so specify this number for splitting the combined ZIP:

```sh
split -b 182 combined.zip pt_
```

Now we should have three files (`pt_aa`, `pt_ab`, `pt_ac`) in current directory.  
To extract them and get the original files (`first.txt` and `second.txt`), run the following command:

```sh
# Unzip the first file to get `first.txt`.
unzip pt_aa

# Unzip the second file to get `second.txt`.
cat pt_ab pt_ac > pt_ad
unzip pt_ad
```

As above, we need to concatenate the 2nd/3rd files before unzipping.  
Finally, we can get the original two files from the combined ZIP file.

## Resources

- [Perception Point](https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/)