# VirusTotal File Scanner (C Implementation)

A C program that scans files using the VirusTotal API for malware detection.

## Features

- Simple command-line interface
- Automatic `.env` file support for API key configuration
- Environment variable fallback support
- Works with any C compiler (gcc, clang, Visual Studio, etc.)
- VS Code debugging support with integrated terminal

## Project Structure

```
Upload-Secure-Sample-with-C/
├── src/                      # All C source files (.c)
│   ├── main.c               # Main UI/UX program
│   └── virustotal_utils.c   # VirusTotal API implementation
├── include/                  # All header files (.h)
│   └── virustotal_utils.h   # API function declarations
├── docs/                     # Project documentation, flowcharts, assets
├── assets/                   # Screenshots, diagrams, additional resources
├── .env                      # Your API key (create this file, hidden from Git)
├── sample_input.txt          # Sample test input file
├── README.md                 # This file
└── .vscode/                  # VS Code configuration
    ├── settings.json         # Workspace settings
    ├── tasks.json            # Build tasks
    ├── launch.json           # Debug/run configurations
    └── c_cpp_properties.json # IntelliSense configuration
```

## Setup

### 1. Install Prerequisites

You'll need to install the following libraries:

- **libcurl** - for HTTP requests
- **cjson** - for JSON parsing
- **gdb** - for debugging (optional, but recommended for VS Code)

See the installation instructions below for your platform.

### 2. Configure API Key

The program supports two methods for setting your VirusTotal API key:

#### Method 1: `.env` File (Recommended)

1. Create a `.env` file in the project root directory
2. Add your API key:
   ```
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```
3. Get your API key from: https://www.virustotal.com/gui/user/[your-username]/apikey

The `.env` file is automatically ignored by Git (via `.gitignore`) to protect your API key.

#### Method 2: Environment Variable

You can also set it as an environment variable:

**Windows PowerShell:**
```powershell
$env:VIRUSTOTAL_API_KEY="your_api_key_here"
```

**Windows CMD:**
```cmd
set VIRUSTOTAL_API_KEY=your_api_key_here
```

**Linux/macOS:**
```bash
export VIRUSTOTAL_API_KEY="your_api_key_here"
```

**Note:** The program checks `.env` file first, then falls back to the environment variable.

## Compile and Run

### Using VS Code (Recommended)

1. **Build**: Press `Ctrl+Shift+B` (or `Cmd+Shift+B` on Mac)
2. **Run with Debugger**: Press `F5`
   - Automatically builds before running
   - Uses integrated terminal (no external window)
   - Full debugging support with breakpoints

### Using Command Line (MSYS2/MinGW)

From the project root directory:

```bash
gcc -o main.exe src/main.c src/virustotal_utils.c -Iinclude -lcurl -lcjson
./main.exe
```

### Using Command Line (Other Compilers)

```bash
gcc -o main.exe src/main.c src/virustotal_utils.c -Iinclude -lcurl -lcjson
```

## Usage

1. Run the compiled program
2. When prompted, enter the filename (or press Enter to use `sample_input.txt`)
3. The program will:
   - Upload the file to VirusTotal
   - Wait for the scan to complete
   - Display the results (harmless/malicious counts)

**Example:**
```
Enter filename (or press Enter for sample_input.txt): sample_input.txt
```

## Installing Prerequisites

### Windows with MSYS2 (Recommended)

1. Install MSYS2 from https://www.msys2.org/

2. Open MSYS2 MinGW 64-bit terminal and install:
   ```bash
   pacman -Syu
   pacman -S mingw-w64-x86_64-gcc
   pacman -S mingw-w64-x86_64-curl
   pacman -S mingw-w64-x86_64-cjson
   pacman -S mingw-w64-x86_64-gdb
   ```

3. Add MSYS2 to your PATH or use the full path to gcc

### Windows with vcpkg

1. Install vcpkg:
   ```powershell
   git clone https://github.com/Microsoft/vcpkg.git
   cd vcpkg
   .\bootstrap-vcpkg.bat
   ```

2. Install libraries:
   ```powershell
   .\vcpkg install curl:x64-windows cjson:x64-windows
   ```

3. Compile with:
   ```bash
   gcc -o main.exe src/main.c src/virustotal_utils.c -Iinclude -IC:/path/to/vcpkg/installed/x64-windows/include -LC:/path/to/vcpkg/installed/x64-windows/lib -lcurl -lcjson
   ```

## VS Code Debugging

The project is configured for VS Code debugging:

- **F5**: Build and run with debugger
- **Breakpoints**: Click in the gutter next to line numbers
- **Debug Controls**: Use the debug toolbar (continue, step over, step into, etc.)
- **Integrated Terminal**: Output appears in VS Code's integrated terminal

The debugger uses gdb and runs in the integrated terminal (no external windows).

## Security Note

- Never commit your `.env` file to Git
- The `.gitignore` file already excludes `.env`
- Keep your API key secret
- The `.env` file is hidden in VS Code's file explorer

## Troubleshooting

**Error: VIRUSTOTAL_API_KEY not found**
- Make sure you've created a `.env` file in the project root
- Check that the file contains: `VIRUSTOTAL_API_KEY=your_key_here`
- Ensure there are no extra spaces or quotes around the key

**Compilation errors about missing headers**
- Make sure you've installed libcurl and cjson
- Check that your compiler can find the include directories
- For VS Code, reload the window after installing libraries

**Linker errors about missing libraries**
- Ensure the library files (.lib or .a) are in your library path
- Make sure you're linking with `-lcurl -lcjson` flags
- Check that MSYS2 libraries are accessible from your PATH

**VS Code IntelliSense errors (red squiggles)**
- These are just warnings and won't prevent compilation
- Reload VS Code window: `Ctrl+Shift+P` → "Reload Window"
- Or reset IntelliSense: `Ctrl+Shift+P` → "C/C++: Reset IntelliSense Database"

**Debugger not working**
- Make sure gdb is installed: `pacman -S mingw-w64-x86_64-gdb`
- Check that the path in `launch.json` matches your gdb location
- Try rebuilding: `Ctrl+Shift+B`

## Development

### Adding New Files

- **Source files (.c)**: Add to `src/` directory
- **Header files (.h)**: Add to `include/` directory
- **Documentation**: Add to `docs/` directory
- **Assets**: Add to `assets/` directory

### Build Configuration

The build process is configured in `.vscode/tasks.json`. The default build task:
- Compiles all `.c` files from `src/`
- Links against `include/` for headers
- Links against libcurl and cjson libraries
