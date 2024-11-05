# DeathSleep

## Usage

### 1. Settings for Compiling Assembly

To compile our `.asm` file, follow the instruction in Visual Studio:

1. Right-click on the solution name in the Solution Explorer.
2. Click on **Build Dependencies** -> **Build Customizations**.
3. Enable **masm** in the Build Customizations window.
4. Click **OK** and close the Window.
5. Right-click on the `Utils.asm` in the Solution Explorer.
6. Click on **Properties**.
7. Select **Microsoft Macro Assembler** in the Property Pages window.
8. Click **Apply** and close the Window.

### 2. Build

Build the solution in Visual Studio.

### 3. Fix the Stack Frame Size

After building, we need to fix the stack frame size with the following command:

```sh
python3 scripts/fixStackFrameSize.py -f DeathSleep.exe
```

Now we can execute the `DeathSleep.exe`.

## Credit

[janoglezcampos](https://github.com/janoglezcampos/DeathSleep)
