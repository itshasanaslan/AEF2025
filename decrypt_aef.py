#!/usr/bin/env python3
import os
import json
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import getpass
import sys
import curses
import time
import glob
from pathlib import Path
from datetime import datetime

class AEF2025Decryptor:
    def __init__(self):
        self.SALT_SIZE = 16
        self.KEY_SIZE = 32
        self.ITERATIONS = 100000
        self.IV_SIZE = 16
        self.progress_callback = None
        self.detailed_progress = {
            'current_operation': '',
            'bytes_processed': 0,
            'total_bytes': 0,
            'start_time': None,
            'current_file': '',
            'files_processed': 0,
            'total_files': 0
        }

    def set_progress_callback(self, callback):
        """Set callback for progress updates"""
        self.progress_callback = callback

    def update_detailed_progress(self, **kwargs):
        """Update detailed progress information"""
        self.detailed_progress.update(kwargs)
        if self.progress_callback:
            self.progress_callback(self.detailed_progress)

    def generate_key(self, password, salt):
        """Generate key using PBKDF2 with SHA256"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=salt,
            iterations=self.ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def decrypt_file(self, encrypted_path, password):
        """Decrypt an AEF2025 encrypted file"""
        try:
            self.update_detailed_progress(
                current_operation="Reading file",
                current_file=os.path.basename(encrypted_path),
                start_time=datetime.now()
            )

            # Read the encrypted file
            with open(encrypted_path, 'rb') as f:
                sealed_data = f.read()

            self.update_detailed_progress(
                current_operation="Extracting components",
                bytes_processed=0,
                total_bytes=len(sealed_data)
            )

            # Extract components
            salt = sealed_data[:self.SALT_SIZE]
            iv = sealed_data[self.SALT_SIZE:self.SALT_SIZE + self.IV_SIZE]
            
            # Extract metadata length and metadata
            metadata_length = int.from_bytes(sealed_data[self.SALT_SIZE + self.IV_SIZE:self.SALT_SIZE + self.IV_SIZE + 4], 'little')
            metadata_start = self.SALT_SIZE + self.IV_SIZE + 4
            
            if metadata_length <= 0 or metadata_start + metadata_length > len(sealed_data):
                print(f"Error: Invalid metadata length: {metadata_length}")
                return False

            metadata_bytes = sealed_data[metadata_start:metadata_start + metadata_length]
            metadata = json.loads(metadata_bytes.decode('utf-8'))

            self.update_detailed_progress(current_operation="Decrypting data")

            # Extract encrypted data
            encrypted_data = sealed_data[metadata_start + metadata_length:]

            # Generate key
            key = self.generate_key(password, salt)

            # Decrypt the data
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # Add PKCS7 padding
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove PKCS7 padding
            padding_length = padded_data[-1]
            decrypted_data = padded_data[:-padding_length]

            if not decrypted_data:
                print("Error: Decryption failed - Incorrect password or corrupted data")
                return False

            self.update_detailed_progress(current_operation="Writing decrypted file")

            # Create output filename
            output_path = os.path.join(
                os.path.dirname(encrypted_path),
                metadata['OriginalName'] + metadata['Extension']
            )

            # Write decrypted data
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            self.update_detailed_progress(current_operation="Complete")
            return True

        except Exception as e:
            print(f"Error during decryption: {str(e)}")
            return False

    def decrypt_directory(self, directory_path, password):
        """Decrypt all .aslan files in a directory"""
        success_count = 0
        fail_count = 0
        total_files = 0

        # Count total files first
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.aslan'):
                    total_files += 1

        if total_files == 0:
            print("No .aslan files found in directory")
            return 0, 0

        self.update_detailed_progress(
            total_files=total_files,
            files_processed=0,
            start_time=datetime.now()
        )

        # Process each file
        current_file = 0
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.aslan'):
                    current_file += 1
                    file_path = os.path.join(root, file)
                    
                    self.update_detailed_progress(
                        files_processed=current_file,
                        current_file=file
                    )

                    if self.decrypt_file(file_path, password):
                        success_count += 1
                    else:
                        fail_count += 1

        return success_count, fail_count

class TerminalUI:
    def __init__(self):
        self.stdscr = curses.initscr()
        curses.start_color()
        curses.use_default_colors()
        
        # Define color pairs
        self.colors = {
            'light': {
                'success': (curses.COLOR_GREEN, -1),
                'error': (curses.COLOR_RED, -1),
                'warning': (curses.COLOR_YELLOW, -1),
                'info': (curses.COLOR_CYAN, -1),
                'header': (curses.COLOR_WHITE, -1),
                'text': (curses.COLOR_WHITE, -1)
            },
            'dark': {
                'success': (curses.COLOR_GREEN, curses.COLOR_BLACK),
                'error': (curses.COLOR_RED, curses.COLOR_BLACK),
                'warning': (curses.COLOR_YELLOW, curses.COLOR_BLACK),
                'info': (curses.COLOR_CYAN, curses.COLOR_BLACK),
                'header': (curses.COLOR_WHITE, curses.COLOR_BLACK),
                'text': (curses.COLOR_WHITE, curses.COLOR_BLACK)
            }
        }
        
        self.current_theme = 'light'
        self.init_colors()
        
        curses.cbreak()
        curses.noecho()
        self.stdscr.keypad(True)
        self.decryptor = AEF2025Decryptor()
        self.decryptor.set_progress_callback(self.update_progress)
        
        # Initialize help text
        self.help_text = [
            "AEF2025 Decryptor Help",
            "=====================",
            "",
            "1. Single File Decryption:",
            "   - Select option 1 from main menu",
            "   - Enter the path to your .aslan file",
            "   - Type the password when prompted",
            "",
            "2. Directory Decryption:",
            "   - Select option 2 from main menu",
            "   - Enter the directory path",
            "   - Type the password when prompted",
            "",
            "3. File Path Tips:",
            "   - Use Tab for auto-completion",
            "   - Use ~ for home directory",
            "   - Use . for current directory",
            "",
            "4. Keyboard Shortcuts:",
            "   - Tab: Auto-complete path",
            "   - Ctrl+T: Toggle theme",
            "   - Ctrl+H: Show this help",
            "   - Esc: Go back/Exit",
            "",
            "Press any key to continue..."
        ]

    def init_colors(self):
        """Initialize color pairs for current theme"""
        for i, (name, (fg, bg)) in enumerate(self.colors[self.current_theme].items(), 1):
            curses.init_pair(i, fg, bg)

    def toggle_theme(self):
        """Toggle between light and dark themes"""
        self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        self.init_colors()
        self.stdscr.clear()
        self.stdscr.refresh()

    def cleanup(self):
        curses.nocbreak()
        self.stdscr.keypad(False)
        curses.echo()
        curses.endwin()

    def format_size(self, size):
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def format_time(self, seconds):
        """Format time in human readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        minutes = seconds / 60
        if minutes < 60:
            return f"{minutes:.1f}m"
        hours = minutes / 60
        return f"{hours:.1f}h"

    def update_progress(self, progress_info):
        """Update progress display with detailed information"""
        self.stdscr.clear()
        
        # Header
        self.stdscr.addstr(0, 0, "AEF2025 Decryptor", curses.A_BOLD | curses.color_pair(5))
        
        # Current operation
        self.stdscr.addstr(2, 0, f"Operation: {progress_info['current_operation']}", 
                          curses.color_pair(4))
        
        # File information
        if progress_info['current_file']:
            self.stdscr.addstr(3, 0, f"File: {progress_info['current_file']}")
        
        # Progress bar
        if progress_info['total_bytes'] > 0:
            progress = (progress_info['bytes_processed'] / progress_info['total_bytes']) * 100
            self.stdscr.addstr(4, 0, f"Progress: {progress:.1f}%")
            self.stdscr.addstr(5, 0, "[" + "=" * int(progress/2) + " " * (50 - int(progress/2)) + "]")
            
            # Size information
            self.stdscr.addstr(6, 0, 
                f"Processed: {self.format_size(progress_info['bytes_processed'])} / "
                f"{self.format_size(progress_info['total_bytes'])}")
        
        # Time information
        if progress_info['start_time']:
            elapsed = (datetime.now() - progress_info['start_time']).total_seconds()
            self.stdscr.addstr(7, 0, f"Time elapsed: {self.format_time(elapsed)}")
        
        # Batch progress
        if progress_info['total_files'] > 0:
            self.stdscr.addstr(8, 0, 
                f"Files: {progress_info['files_processed']}/{progress_info['total_files']} "
                f"({(progress_info['files_processed']/progress_info['total_files']*100):.1f}%)")
        
        self.stdscr.refresh()

    def show_message(self, message, color_pair=0):
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "AEF2025 Decryptor", curses.A_BOLD | curses.color_pair(5))
        self.stdscr.addstr(2, 0, message, color_pair)
        self.stdscr.addstr(4, 0, "Press any key to continue...")
        self.stdscr.refresh()
        self.stdscr.getch()

    def get_input(self, prompt, y, x, hidden=False, completer=None):
        self.stdscr.addstr(y, x, prompt)
        self.stdscr.refresh()
        
        if hidden:
            curses.noecho()
        else:
            curses.echo()
        
        input_str = ""
        while True:
            char = self.stdscr.getch()
            
            if char == 27:  # ESC
                return None
            elif char == 9 and completer:  # Tab
                # Handle auto-completion
                matches = completer(input_str)
                if matches:
                    input_str = matches[0]
                    self.stdscr.addstr(y, x + len(prompt), input_str)
            elif char == 10:  # Enter
                break
            elif char == 127 or char == 8:  # Backspace
                if input_str:
                    input_str = input_str[:-1]
                    self.stdscr.addstr(y, x + len(prompt) + len(input_str), " ")
                    self.stdscr.move(y, x + len(prompt) + len(input_str))
            else:
                input_str += chr(char)
                if hidden:
                    self.stdscr.addstr(y, x + len(prompt) + len(input_str) - 1, "*")
                else:
                    self.stdscr.addstr(y, x + len(prompt) + len(input_str) - 1, chr(char))
        
        curses.noecho()
        return input_str

    def path_completer(self, partial):
        """Complete file paths"""
        if not partial:
            return ["./", "../", "~/"]
        
        # Handle home directory
        if partial.startswith("~"):
            partial = os.path.expanduser(partial)
        
        # Get directory and pattern
        directory = os.path.dirname(partial)
        pattern = os.path.basename(partial) + "*"
        
        try:
            # Get matching files
            matches = glob.glob(os.path.join(directory, pattern))
            return [os.path.relpath(m) for m in matches]
        except:
            return []

    def show_help(self):
        """Display help information"""
        self.stdscr.clear()
        for i, line in enumerate(self.help_text):
            self.stdscr.addstr(i, 0, line)
        self.stdscr.refresh()
        self.stdscr.getch()

    def main_menu(self):
        while True:
            self.stdscr.clear()
            self.stdscr.addstr(0, 0, "AEF2025 Decryptor", curses.A_BOLD | curses.color_pair(5))
            self.stdscr.addstr(2, 0, "1. Decrypt Single File")
            self.stdscr.addstr(3, 0, "2. Decrypt Directory")
            self.stdscr.addstr(4, 0, "3. Help")
            self.stdscr.addstr(5, 0, "4. Toggle Theme")
            self.stdscr.addstr(6, 0, "5. Exit")
            self.stdscr.addstr(8, 0, "Select an option (1-5): ")
            self.stdscr.refresh()

            choice = self.stdscr.getch()
            if choice == ord('1'):
                self.decrypt_single_file()
            elif choice == ord('2'):
                self.decrypt_directory()
            elif choice == ord('3'):
                self.show_help()
            elif choice == ord('4'):
                self.toggle_theme()
            elif choice == ord('5'):
                break
            elif choice == 9:  # Tab
                self.toggle_theme()
            elif choice == 12:  # Ctrl+L
                self.show_help()

    def decrypt_single_file(self):
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Enter file path:", curses.A_BOLD | curses.color_pair(5))
        file_path = self.get_input("File: ", 1, 0, completer=self.path_completer)
        
        if file_path is None:  # ESC pressed
            return
            
        if not os.path.exists(file_path):
            self.show_message("Error: File not found!", curses.color_pair(2))
            return

        if not file_path.endswith('.aslan'):
            self.show_message("Error: File must have .aslan extension!", curses.color_pair(2))
            return

        password = self.get_input("Password: ", 2, 0, hidden=True)

        if self.decryptor.decrypt_file(file_path, password):
            self.show_message("Decryption successful!", curses.color_pair(1))
        else:
            self.show_message("Decryption failed!", curses.color_pair(2))

    def decrypt_directory(self):
        self.stdscr.clear()
        self.stdscr.addstr(0, 0, "Enter directory path:", curses.A_BOLD | curses.color_pair(5))
        dir_path = self.get_input("Directory: ", 1, 0, completer=self.path_completer)
        
        if dir_path is None:  # ESC pressed
            return
            
        if not os.path.exists(dir_path):
            self.show_message("Error: Directory not found!", curses.color_pair(2))
            return

        password = self.get_input("Password: ", 2, 0, hidden=True)

        success, fail = self.decryptor.decrypt_directory(dir_path, password)
        self.show_message(f"Decryption complete!\nSuccess: {success}\nFailed: {fail}", 
                         curses.color_pair(1) if fail == 0 else curses.color_pair(3))

def main():
    if len(sys.argv) > 1:
        # Command line mode
        encrypted_path = sys.argv[1]
        if not os.path.exists(encrypted_path):
            print(f"Error: File not found: {encrypted_path}")
            return

        if not encrypted_path.endswith('.aslan'):
            print("Error: File must have .aslan extension")
            return

        password = getpass.getpass("Enter password: ")
        decryptor = AEF2025Decryptor()
        
        if decryptor.decrypt_file(encrypted_path, password):
            print("Decryption completed successfully!")
        else:
            print("Decryption failed!")
    else:
        # Terminal UI mode
        try:
            ui = TerminalUI()
            ui.main_menu()
        except Exception as e:
            print(f"Error: {str(e)}")
        finally:
            if 'ui' in locals():
                ui.cleanup()

if __name__ == "__main__":
    main() 