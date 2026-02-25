#!/bin/bash

# --- Configuration ---
# Define the final destination for executables and data
# This script will place everything in the current directory (project root)
DEST_DIR="." # Current directory (project root)

# --- Dependency Check and Install Function ---
check_dependency() {
    local cmd="$1"
    local package="$2"
    local apt_update_output_file=$(mktemp) # Create a temporary file for apt update output
    local apt_update_failed=0 # Flag to track if apt update had a non-zero exit

    if ! command -v "$cmd" &> /dev/null; then
        echo "Dependency '$cmd' not found."
        
        # Attempt to install if apt is available
        if command -v apt &> /dev/null; then
            echo "Attempting to install '$package' using apt..."
            
            # --- Perform apt update, capturing output and handling specific errors ---
            echo "Running: sudo apt update (ignoring non-critical repository errors for now)..."
            # We use 'tee' to show output to user AND capture to file
            if sudo apt update 2>&1 | tee "$apt_update_output_file"; then
                echo "apt update completed without critical errors."
            else
                apt_update_failed=1
                # Check for the specific "Release file is not valid yet" message
                if grep -q "Release file for .* is not valid yet" "$apt_update_output_file"; then
                    echo "WARNING: An 'apt update' error occurred:"
                    grep "Release file for .* is not valid yet" "$apt_update_output_file"
                    echo "  This usually means a timestamp issue for a repository (e.g., your system clock vs. server)."
                    echo "  We will *attempt* to install '$package' anyway, but it might not be the latest version."
                    echo "  You may need to fix your repository configuration or system clock later for full updates."
                else
                    echo "CRITICAL ERROR: 'sudo apt update' failed for an unknown reason (not a timestamp issue)."
                    echo "  Please resolve the apt update issues manually, then try again."
                    rm "$apt_update_output_file"
                    exit 1 # Exit for critical apt update failure
                fi
            fi
            
            # --- Now attempt to install the package ---
            echo "Running: sudo apt install -y $package"
            if sudo apt install -y "$package"; then
                echo "Successfully installed '$package'."
            else
                echo "Error: Failed to install '$package' automatically."
                echo "  This could be due to the previous 'apt update' issue or other reasons."
                echo "  Please install it manually: sudo apt update && sudo apt install $package"
                rm "$apt_update_output_file"
                exit 1 # Exit if apt install fails
            fi
        else
            echo "Error: '$cmd' not found and 'apt' package manager not detected."
            echo "Please install '$package' manually using your distribution's package manager."
            exit 1 # Exit if apt is not available
        fi
    fi
    rm "$apt_update_output_file" # Clean up temporary file
}

# --- Function to check OpenSSL development headers ---
check_openssl_headers() {
    echo "Checking for OpenSSL development headers..."
    
    # Check if openssl/ec.h exists
    if [ ! -f "/usr/include/openssl/ec.h" ]; then
        echo "OpenSSL development headers not found. Installing libssl-dev..."
        check_dependency "openssl" "libssl-dev"
    else
        echo "OpenSSL development headers are present."
    fi
}

# --- Main Installation Process ---

echo "--- Milk Sad Generator Installation Script ---"
echo "Starting installation process. This may take a few moments..."
echo "NEW FEATURE: Now generates Legacy, Nested SegWit, and Native SegWit addresses!"
echo "COMPATIBILITY: Fixed C++11 compatibility issues"
echo ""

# --- 1. Check for Required Dependencies and Install if Missing ---
echo "Checking for essential build tools and libraries..."
check_dependency "g++" "build-essential"
check_dependency "make" "build-essential"
check_dependency "qmake" "qt5-qmake" # For Qt projects

# Enhanced OpenSSL checks for CLI only
check_openssl_headers

check_dependency "libqt5widgets5-dev" "qtbase5-dev" # For Qt GUI development (includes core, gui, widgets)

echo "All required dependencies are present or have been installed. Proceeding with compilation."
echo ""

# --- 2. Compile CLI Application ---
echo "--- Compiling CLI application (milk_sad_generator) ---"
echo "FEATURE UPDATE: Now generates Legacy, Nested SegWit, and Native SegWit addresses from BIP39 mnemonics"
echo "COMPATIBILITY: Using C++11 standard for maximum compatibility"
CLI_DIR="src/cli"

# Clean previous CLI build artifacts
echo "Cleaning previous CLI build artifacts in $CLI_DIR..."
rm -f "$CLI_DIR/milk_sad_generator" "$CLI_DIR/milk_sad_generator.o"

# Navigate to CLI directory and compile
cd "$CLI_DIR" || { echo "Error: Could not enter $CLI_DIR. Aborting."; exit 1; }

# Enhanced compilation with additional flags for OpenSSL and C++11 features
echo "Compiling CLI application with enhanced cryptographic features..."
echo "Including SegWit address generation (Bech32 and P2SH-P2WPKH support)..."
echo "Using C++11 standard for maximum compatibility..."
g++ -std=gnu++11 -Wall -Wextra -O2 -pthread milk_sad_generator.cpp -o milk_sad_generator \
    -I/usr/include/openssl \
    -L/usr/lib/x86_64-linux-gnu \
    -lcrypto -lssl -lrt || { 
    echo "CLI compilation failed. Aborting."; 
    echo "Troubleshooting tips:";
    echo "1. Ensure libssl-dev is installed: sudo apt install libssl-dev";
    echo "2. Check if OpenSSL headers are in /usr/include/openssl/";
    echo "3. Verify library paths: ldconfig -p | grep ssl";
    echo "4. Check for missing includes or C++11 compatibility issues";
    exit 1; 
}

echo "CLI compilation successful."

# Return to project root
cd - > /dev/null
echo ""

# --- 3. Compile GUI Application ---
echo "--- Compiling GUI application (milk_sad_generator_gui) ---"
GUI_DIR="src/gui"
GUI_PROJ="mnemonic_generator.pro"

# Clean previous GUI build artifacts
echo "Cleaning previous GUI build artifacts in $GUI_DIR..."
cd "$GUI_DIR" || { echo "Error: Could not enter $GUI_DIR. Aborting."; exit 1; }
make clean > /dev/null 2>&1
cd - > /dev/null

# Navigate to GUI directory, run qmake, then make - WITHOUT MODIFYING .pro FILE
cd "$GUI_DIR" || { echo "Error: Could not enter $GUI_DIR. Aborting."; exit 1; }
echo "Running qmake in $GUI_DIR..."
qmake "$GUI_PROJ" || { echo "qmake for GUI failed. Aborting."; exit 1; }

echo "Running make in $GUI_DIR..."
make || { echo "GUI compilation failed. Aborting."; exit 1; }

echo "GUI compilation successful."

# Return to project root
cd - > /dev/null
echo ""

# --- 4. Move Executables to Root ---
echo "--- Moving executables to project root ($DEST_DIR) ---"
CLI_EXECUTABLE="src/cli/milk_sad_generator"
GUI_EXECUTABLE="src/gui/milk_sad_generator_gui"

if [ -f "$CLI_EXECUTABLE" ]; then
    mv "$CLI_EXECUTABLE" "$DEST_DIR/" || { echo "Failed to move CLI executable. Aborting."; exit 1; }
    echo "Moved '$CLI_EXECUTABLE' to '$DEST_DIR/'"
    # Make executable
    chmod +x "$DEST_DIR/milk_sad_generator"
else
    echo "Warning: CLI executable '$CLI_EXECUTABLE' not found. It might not have compiled."
fi

if [ -f "$GUI_EXECUTABLE" ]; then
    mv "$GUI_EXECUTABLE" "$DEST_DIR/" || { echo "Failed to move GUI executable. Aborting."; exit 1; }
    echo "Moved '$GUI_EXECUTABLE' to '$DEST_DIR/'"
    # Make executable
    chmod +x "$DEST_DIR/milk_sad_generator_gui"
else
    echo "Warning: GUI executable '$GUI_EXECUTABLE' not found. It might not have compiled."
fi
echo ""

# --- 5. Ensure Data/Asset Folders are Correctly Placed for Executables ---
echo "Handling Pic/ directory for GUI executable..."
if [ -d "src/gui/Pic" ]; then
    if [ ! -d "Pic" ]; then
        echo "  Moving src/gui/Pic/ to project root (./Pic/)..."
        mv src/gui/Pic . || { echo "Error: Failed to move Pic/ to root. Aborting."; exit 1; }
        echo "  Pic/ successfully moved to project root."
    else
        echo "  Pic/ directory already exists at project root."
        if [ ! -f "Pic/1_0LOPQwRdahE_ABkF8idXgg.png" ]; then
            echo "  WARNING: Pic/ at root does NOT contain '1_0LOPQwRdahE_ABkF8idXgg.png'."
            echo "  Copying missing image from src/gui/Pic/ to existing Pic/ at root."
            cp -r src/gui/Pic/* Pic/ || { echo "Error: Failed to copy missing Pic/ content. Aborting."; exit 1; }
        fi
    fi
else
    echo "  WARNING: src/gui/Pic/ not found. Ensure Pic/ is correctly placed for GUI."
fi

echo "Handling Wordlist/ directory..."
if [ ! -d "Wordlist" ]; then
    echo "  WARNING: Wordlist/ directory not found at root. Applications may not function correctly."
    echo "  Creating empty Wordlist directory. Please add BIP39 wordlist files."
    mkdir -p Wordlist
else
    echo "  Wordlist/ directory exists at root."
    # Check if wordlist files exist
    if [ ! -f "Wordlist/english.txt" ]; then
        echo "  WARNING: Standard wordlist files (e.g., english.txt) not found in Wordlist/ directory."
        echo "  Please download BIP39 wordlists and place them in Wordlist/ directory."
    fi
fi
echo ""

# --- 6. Create configuration and documentation ---
echo "--- Creating configuration and documentation ---"
if [ ! -f "README.txt" ]; then
    cat > "README.txt" << EOF
Milk Sad Generator - Installation Complete

Applications:
- milk_sad_generator: CLI version with enhanced address generation
- milk_sad_generator_gui: GUI version (original functionality)

NEW FEATURES (CLI Version):
- Generates THREE types of Bitcoin addresses from each mnemonic:
  * Legacy (P2PKH) - starts with '1'
  * Nested SegWit (P2SH-P2WPKH) - starts with '3'  
  * Native SegWit (Bech32) - starts with 'bc1'
- C++11 compatible - works on older systems
- Libbitcoin Explorer v3.0.0-3.6.0 compatible
- Supports multiple BIP39 wordlists
- Progress tracking and resume capability
- Enhanced cryptographic security

GUI Version:
- Original mnemonic generation functionality

Address Types Explained:
- Legacy (P2PKH): Compatible with all wallets, higher transaction fees
- Nested SegWit: Backward compatible, medium transaction fees
- Native SegWit: Modern standard, lowest transaction fees

Required Wordlists:
Place BIP39 wordlist files in the Wordlist/ directory. 
Standard files include: english.txt, spanish.txt, french.txt, etc.

Each wordlist must contain exactly 2048 words.

OpenSSL Dependencies:
The CLI application requires OpenSSL libraries for cryptographic operations.
If you encounter library errors, install: sudo apt install libssl-dev

Usage:
CLI: ./milk_sad_generator
GUI: ./milk_sad_generator_gui

Output Format (CLI):
For single generation: Detailed information for all three address types
For batch generation: legacy_address nested_segwit_address native_segwit_address private_key

Storage Requirements:
Full 32-bit timestamp range: ~1.5-2TB (due to three addresses per key)
Consider using date ranges for manageable file sizes.

Technical Details:
- Uses C++11 standard for maximum compatibility
- No C++17 features required
- Compatible with older compilers and systems

Developed by z1ph1us
EOF
    echo "Created README.txt with updated usage instructions."
else
    # Update existing README if needed
    if ! grep -q "Native SegWit" "README.txt"; then
        echo "Updating README.txt with new SegWit features..."
        cat >> "README.txt" << EOF

NEW UPDATE: Now generates Legacy, Nested SegWit, and Native SegWit addresses!
- Legacy (P2PKH): Starts with '1'
- Nested SegWit (P2SH-P2WPKH): Starts with '3'
- Native SegWit (Bech32): Starts with 'bc1'

Each private key now produces three different addresses for maximum compatibility.

TECHNICAL: Now uses C++11 standard for better compatibility with older systems.
EOF
    fi
fi

# --- 7. Final Cleanup (Optional) ---
echo "--- Performing final cleanup of build directories ---"
# Clean up remaining build artifacts in source directories
cd src/cli && rm -f *.o && cd - > /dev/null
cd src/gui && make clean > /dev/null && cd - > /dev/null

echo ""
echo "=== Installation complete! ==="
echo "NEW: CLI now generates Legacy, Nested SegWit, and Native SegWit addresses!"
echo "COMPATIBILITY: Fixed C++11 compatibility - no more compilation errors!"
echo ""
echo "You can now run your applications from the project root:"
echo "  CLI: ./milk_sad_generator"
echo "  GUI: ./milk_sad_generator_gui"
echo ""
echo "Important: Ensure you have BIP39 wordlist files in the Wordlist/ directory."
echo "You can download standard wordlists from:"
echo "https://github.com/bitcoin/bips/tree/master/bip-0039"
echo ""
echo "Storage Note: Full timestamp range will generate ~1.5-2TB of data"
echo "Consider using date ranges for practical usage."
echo ""
