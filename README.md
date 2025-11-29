# VirusTotal File Scanner (C Implementation)

A C program that scans files using the VirusTotal API for malware detection.

## Features

- Simple command-line interface
- Automatic `.env` file support for API key configuration
- Environment variable fallback support
- Works with any C compiler (gcc, clang, Visual Studio, etc.)

## Setup

### 1. Install Prerequisites

You'll need to install the following libraries:

- **libcurl** - for HTTP requests
- **cjson** - for JSON parsing

See the installation instructions below for your platform.

### 2. Configure API Key

The program supports two methods for setting your VirusTotal API key:

#### Method 1: `.env` File (Recommended)

1. Copy the template file:
   ```
   Copy `env.template` and rename it to `.env`
   ```

2. Edit the `.env` file and add your API key:
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

### 3. Compile and Run

The program can be compiled with any C compiler. The `.env` file will be automatically read when you run the program from your IDE or compiler's run button.

#### Using GCC (MinGW/MSYS2):
```bash
gcc -o main.exe main.c config/virustotal_utils.c -lcurl -lcjson
```

#### Using Visual Studio:
Create a project and add both `main.c` and `config/virustotal_utils.c` to it. Configure the linker to include `curl` and `cjson` libraries.

## Usage

1. Run the compiled program
2. When prompted, enter the filename from the `data/` folder (e.g., `example.txt`)
3. The program will:
   - Upload the file to VirusTotal
   - Wait for the scan to complete
   - Display the results (harmless/malicious counts)

## Project Structure

```
Upload-Secure-Sample-with-C/
├── config/
│   ├── virustotal_utils.h      # API function declarations
│   └── virustotal_utils.c      # VirusTotal API implementation
├── data/
│   └── example.txt             # Sample file for testing
├── .env                        # Your API key (create this file, not in Git)
├── .env.example                # Template for .env file
├── .gitignore                  # Git ignore file (includes .env)
├── main.c                      # Main UI/UX program
└── README.md                   # This file
```

## Installing Prerequisites

### Windows with vcpkg (Recommended)

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
   gcc -o main.exe main.c config/virustotal_utils.c -IC:/path/to/vcpkg/installed/x64-windows/include -LC:/path/to/vcpkg/installed/x64-windows/lib -lcurl -lcjson
   ```

### Windows with MSYS2

1. Install MSYS2 from https://www.msys2.org/

2. Open MSYS2 terminal and install:
   ```bash
   pacman -Syu
   pacman -S mingw-w64-x86_64-gcc
   pacman -S mingw-w64-x86_64-curl
   pacman -S mingw-w64-x86_64-cjson
   ```

3. Compile from MSYS2 terminal:
   ```bash
   gcc -o main.exe main.c config/virustotal_utils.c -lcurl -lcjson
   ```

## Running from Your IDE/Compiler

When you use your compiler's "Run" button (e.g., in VS Code, Visual Studio, Code::Blocks, etc.), the program will automatically:

1. Read the `.env` file from the project root directory
2. Use your API key to connect to VirusTotal
3. Work exactly as if run from terminal

**Important:** Make sure the `.env` file is in the same directory as `main.c` (the project root).

## Security Note

- Never commit your `.env` file to Git
- The `.gitignore` file already excludes `.env`
- Keep your API key secret

## Troubleshooting

**Error: VIRUSTOTAL_API_KEY not found**
- Make sure you've created a `.env` file in the project root
- Check that the file contains: `VIRUSTOTAL_API_KEY=your_key_here`
- Ensure there are no extra spaces or quotes around the key

**Compilation errors about missing headers**
- Make sure you've installed libcurl and cjson
- Check that your compiler can find the include directories

**Linker errors about missing libraries**
- Ensure the library files (.lib or .a) are in your library path
- Make sure you're linking with `-lcurl -lcjson` flags

