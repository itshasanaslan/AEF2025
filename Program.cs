using AEF2025;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace AEF2025
{
    /// <summary>
    /// The main program class that provides the user interface and coordinates the application's functionality.
    /// </summary>
    class Program
    {
        /// <summary>
        /// The path to the password hash file (used by PasswordManager, though not directly in Program's main logic).
        /// </summary>
        private static readonly string PASSWORD_HASH_PATH = "password_hash.dat";

        /// <summary>
        /// The password manager instance.
        /// </summary>
        private static PasswordManager _passwordManager;

        // Operator instance is not used, FileSealer static methods are used directly.
        // private static Operator _operator;

        /// <summary>
        /// The currently active password for encryption/decryption operations.
        /// </summary>
        private static string currentPassword;

        // Semaphore for limiting concurrent file operations
        private static readonly int MaxConcurrentTasks = Environment.ProcessorCount * 2;
        private static readonly SemaphoreSlim semaphore = new SemaphoreSlim(MaxConcurrentTasks);

        // Locks for thread-safe console writing and password access
        private static readonly object consoleLock = new object();
        private static readonly object passwordLock = new object();

        /// <summary>
        /// The main entry point of the application.
        /// </summary>
        /// <param name="args">Command line arguments.</param>
        static async Task Main(string[] args)
        {
            Console.OutputEncoding = System.Text.Encoding.UTF8;
            Console.CursorVisible = false;

            try
            {
                ShowSplashScreen();
                InitializeComponents();
                await RunProgram();
            }
            catch (Exception ex)
            {
                WriteError($"\n--- A fatal error occurred ---");
                WriteError($"Message: {ex.Message}");
                WriteError($"Please try restarting the application.");
                Logger.LogError($"Fatal error: {ex.Message}{Environment.NewLine}{ex.StackTrace}");
                Console.WriteLine("\nPress any key to exit.");
                Console.ReadKey();
            }
            finally
            {
                Console.CursorVisible = true;
            }
        }

        private static void ShowSplashScreen()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(@"
 █████╗ ███████╗███████╗    ███████╗██╗███╗   ██╗███████╗
██╔══██╗██╔════╝██╔════╝    ██╔════╝██║████╗  ██║██╔════╝
███████║█████╗  █████╗      █████╗  ██║██╔██╗ ██║█████╗  
██╔══██║██╔══╝  ██╔══╝      ██╔══╝  ██║██║╚██╗██║██╔══╝  
██║  ██║███████╗██║         ██║     ██║██║ ╚████║███████╗
╚═╝  ╚═╝╚══════╝╚═╝         ╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝
");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("   AEF2025 - Advanced Encryption Framework");
            Console.WriteLine("   Version 1.0.0");
            Console.ResetColor();
            Console.WriteLine("   Created by Hasan Aslan (github.com/itshasanaslan)");
            Console.WriteLine("\nInitializing...");
            Thread.Sleep(2000);
            Console.Clear();
        }

        /// <summary>
        /// Initializes the application components.
        /// </summary>
        private static void InitializeComponents()
        {
            Logger.LogInfo("Initializing components...");
            _passwordManager = new PasswordManager(PASSWORD_HASH_PATH);
            // _operator = new Operator(); // Not currently used
            Logger.LogInfo("Components initialized.");
        }

        /// <summary>
        /// Runs the main program loop and user interface.
        /// </summary>
        private static async Task RunProgram()
        {
            WriteHeader("Welcome to AEF2025 - Advanced Encryption Framework (v1.0.0)");

            // Initial Password Setup
            bool passwordSet = false;
            while (!passwordSet)
            {
                try
                {
                    if (string.IsNullOrEmpty(GetPassword()))
                    {
                        WriteInfo("Please set an initial password (5-20 characters): ");
                        string initialPassword = ReadPassword();
                        
                        if (initialPassword.Length < 5 || initialPassword.Length > 20)
                        {
                            WriteError("Password must be between 5 and 20 characters. Please try again.");
                            continue;
                        }

                        SetPassword(initialPassword);
                        WriteSuccess("Initial password set.");

                        try
                        {
                            WriteWarning("Saving password hint (Note: Default method is insecure!)...");
                            PasswordManager.SavePassword(GetPassword());
                            WriteSuccess("Password hint saved successfully!");
                        }
                        catch (Exception ex)
                        {
                            WriteWarning($"Could not save password hint: {ex.Message}");
                            Logger.LogWarning($"Failed to save password hint: {ex.Message}");
                        }
                    }
                    passwordSet = true;
                }
                catch (Exception ex)
                {
                    WriteError($"Error setting password: {ex.Message}");
                    WriteInfo("Please try again.");
                }
            }

            while (true)
            {
                try
                {
                    Console.Clear();
                    WriteHeader("File Encryption System - Main Menu");
                    WriteMenu("1. 🔒 Encrypt Files/Folder");
                    WriteMenu("2. 🔓 Decrypt Files/Folder");
                    WriteMenu("3. 🔑 Change Password");
                    WriteMenu("4. 💡 Show Password Hint");
                    WriteMenu("5. 🧪 Test Encryption/Decryption");
                    WriteMenu("6. 🚪 Exit");
                    ShowFooter();
                    WriteInfo("\nSelect an option (1-6): ");

                    var choice = Console.ReadLine();
                    Console.Clear();

                    switch (choice)
                    {
                        case "1":
                            await ProcessFolder(true);
                            break;
                        case "2":
                            await ProcessFolder(false);
                            break;
                        case "3":
                            await ChangePassword();
                            break;
                        case "4":
                            ShowPasswordHint();
                            break;
                        case "5":
                            await TestEncryptionDecryption();
                            break;
                        case "6":
                            WriteSuccess("Thank you for using the File Encryption System!");
                            return;
                        default:
                            WriteError("Invalid option. Please try again.");
                            break;
                    }
                }
                catch (Exception ex)
                {
                    WriteError($"\n--- An error occurred during operation ---");
                    WriteError($"Message: {ex.Message}");
                    WriteInfo("The application will continue running.");
                    Logger.LogError($"Operation failed: {ex.Message}");
                }

                WriteInfo("\nPress any key to return to the menu...");
                Console.ReadKey();
            }
        }

        /// <summary>
        /// Processes a folder for encryption or decryption.
        /// </summary>
        /// <param name="isEncryption">True for encryption, false for decryption.</param>
        private static async Task ProcessFolder(bool isEncryption)
        {
            string operation = isEncryption ? "Encrypt" : "Decrypt";
            WriteHeader($"{operation} Files");
            
            while (true)
            {
                try
                {
                    WriteInfo("Enter folder path (press Enter for current directory): ");
                    string path = Console.ReadLine();

                    if (string.IsNullOrWhiteSpace(path))
                    {
                        path = Directory.GetCurrentDirectory();
                    }

                    if (!Directory.Exists(path))
                    {
                        WriteError($"Directory not found: {path}");
                        WriteInfo("Please enter a valid directory path.");
                        continue;
                    }

                    WriteInfo($"Scanning directory: {path}...");
                    var files = GetFilesToProcess(path, isEncryption);

                    if (!files.Any())
                    {
                        WriteWarning($"No files found to {operation.ToLower()} in {path}");
                        WriteInfo("Please try a different directory or ensure files are present.");
                        return;
                    }

                    WriteSuccess($"Found {files.Count} files to {operation.ToLower()}.");
                    WriteInfo("Starting processing (Press Esc to cancel)...");

                    await ProcessFilesWithProgress(files, isEncryption);
                    return;
                }
                catch (Exception ex)
                {
                    WriteError($"Error processing folder: {ex.Message}");
                    WriteInfo("Would you like to try again? (Y/N): ");
                    if (Console.ReadLine()?.ToUpper() != "Y")
                    {
                        return;
                    }
                }
            }
        }

        /// <summary>
        /// Gets a list of files to process based on encryption or decryption mode.
        /// </summary>
        private static List<string> GetFilesToProcess(string path, bool isEncryption)
        {
            var searchPattern = isEncryption ? "*.*" : "*.aslan";
            try
            {
                return Directory.GetFiles(path, searchPattern, SearchOption.AllDirectories)
                                .Where(f =>
                                {
                                    // Ensure we don't try to encrypt already encrypted or decrypt non-encrypted
                                    bool hasAslanExtension = f.EndsWith(".aslan", StringComparison.OrdinalIgnoreCase);
                                    return isEncryption ? !hasAslanExtension : hasAslanExtension;
                                })
                                .ToList();
            }
            catch (UnauthorizedAccessException ex)
            {
                WriteError($"Permission error scanning directory {path}: {ex.Message}");
                WriteWarning("  -> Try running as administrator or check folder permissions.");
                Logger.LogError($"Permission error scanning {path}: {ex.Message}");
                return new List<string>(); // Return empty list on permission error
            }
            catch (Exception ex)
            {
                WriteError($"Error scanning directory {path}: {ex.Message}");
                Logger.LogError($"Error scanning {path}: {ex.Message}");
                return new List<string>();
            }
        }

        /// <summary>
        /// Processes a single file for encryption or decryption, including error handling.
        /// </summary>
        private static async Task ProcessFile(string filePath, bool isEncryption)
        {
            FileItem fileItem = null;
            try
            {
                fileItem = new FileItem(filePath); // Initialize here to use in catch blocks
                string targetPath;

                if (isEncryption)
                {
                    targetPath = filePath + ".aslan";
                }
                else
                {
                    targetPath = Path.Combine(
                        Path.GetDirectoryName(filePath),
                        Path.GetFileNameWithoutExtension(filePath)
                    );
                    // DecryptFile will handle restoring the original extension from metadata
                }

                // Check if target exists before starting (optional but can prevent issues)
                if (File.Exists(targetPath))
                {
                    WriteWarning($"! Target file '{Path.GetFileName(targetPath)}' already exists. Skipping.");
                    Logger.LogWarning($"Skipped {fileItem.FileName}: Target file {targetPath} exists.");
                    return;
                }

                if (isEncryption)
                {
                    await EncryptFile(fileItem, targetPath);
                }
                else
                {
                    await DecryptFile(fileItem, targetPath);
                }

                lock (consoleLock)
                {
                    WriteSuccess($"✓ {(isEncryption ? "Encrypted" : "Decrypted")}: {fileItem.FileName}");
                }
            }
            catch (UnauthorizedAccessException uae)
            {
                lock (consoleLock)
                {
                    WriteError($"✗ Permission Error processing {Path.GetFileName(filePath)}: Access denied.");
                    WriteWarning("  -> Please check file/folder permissions.");
                    WriteWarning("  -> Try running the application as an administrator.");
                }
                if (fileItem != null) Logger.LogError($"Permission error: {uae.Message}", fileItem);
                else Logger.LogError($"Permission error on {filePath}: {uae.Message}");
            }
            catch (IOException ioe)
            {
                lock (consoleLock)
                {
                    WriteError($"✗ I/O Error processing {Path.GetFileName(filePath)}: {ioe.Message}");
                    WriteWarning("  -> The file might be in use by another program or inaccessible.");
                }
                if (fileItem != null) Logger.LogError($"I/O error: {ioe.Message}", fileItem);
                else Logger.LogError($"I/O error on {filePath}: {ioe.Message}");
            }
            catch (Exception ex)
            {
                lock (consoleLock)
                {
                    WriteError($"✗ Error processing {Path.GetFileName(filePath)}: {ex.Message}");
                }
                if (fileItem != null) Logger.LogError($"General error: {ex.Message}", fileItem);
                else Logger.LogError($"General error on {filePath}: {ex.Message}");
            }
        }

        /// <summary>
        /// Encrypts a single file.
        /// </summary>
        private static async Task EncryptFile(FileItem fileItem, string targetPath)
        {
            string originalPath = fileItem.FullPath;
            string encryptedPath = null;
            
            try
            {
                if (string.IsNullOrEmpty(currentPassword))
                {
                    throw new Exception("Password is not set. Cannot encrypt.");
                }

                WriteInfo($"  Encrypting {fileItem.FileName}...");
                
                // Ensure file data is read before encryption
                if (fileItem.Data == null || fileItem.Data.Count == 0)
                {
                    fileItem.ReadFileAsByteList();
                }

                // Get the original name data to store in the encrypted file
                byte[] originalNameData = fileItem.GetOriginalNameAsBytes();
                
                // Encrypt the file
                var encryptedData = await Task.Run(() => FileSealer.SealFile(fileItem, currentPassword));

                if (encryptedData == null || encryptedData.Count == 0)
                {
                    throw new Exception("Encryption failed: No data was returned");
                }

                // Generate a new name for the encrypted file
                encryptedPath = fileItem.GenerateEncryptedName();

                // Write the encrypted data to the new path
                await File.WriteAllBytesAsync(encryptedPath, encryptedData.ToArray());

                // Verify the encrypted file was written successfully
                if (!File.Exists(encryptedPath))
                {
                    throw new Exception("Failed to create encrypted file");
                }

                var encryptedFileInfo = new FileInfo(encryptedPath);
                if (encryptedFileInfo.Length == 0)
                {
                    throw new Exception("Encrypted file is empty");
                }

                // Verify we can read the encrypted file
                try
                {
                    byte[] verifyBytes = await File.ReadAllBytesAsync(encryptedPath);
                    if (verifyBytes.Length == 0)
                    {
                        throw new Exception("Could not verify encrypted file");
                    }
                }
                catch (Exception ex)
                {
                    throw new Exception($"Failed to verify encrypted file: {ex.Message}");
                }

                // Only after all verifications, delete the original file
                if (File.Exists(originalPath))
                {
                    File.Delete(originalPath);
                }

                WriteSuccess($"  Successfully encrypted {fileItem.FileName}");
            }
            catch (Exception ex)
            {
                WriteError($"  Encryption failed for {fileItem.FileName}: {ex.Message}");
                Logger.LogError($"Encryption failed: {ex.Message}", fileItem);

                // Clean up the encrypted file if it exists
                if (encryptedPath != null && File.Exists(encryptedPath))
                {
                    try 
                    { 
                        File.Delete(encryptedPath); 
                        WriteInfo("  Cleaned up partial encrypted file."); 
                    }
                    catch { }
                }
            }
        }

        /// <summary>
        /// Decrypts a single file.
        /// </summary>
        private static async Task DecryptFile(FileItem fileItem, string targetPath)
        {
            string encryptedPath = fileItem.FullPath;
            string decryptedPath = null;
            try
            {
                if (string.IsNullOrEmpty(currentPassword))
                {
                    WriteError("Password is not set. Cannot decrypt.");
                    return;
                }

                WriteInfo($"  Decrypting {fileItem.FileName}...");

                // Ensure we read the encrypted file data
                if (fileItem.Data == null || fileItem.Data.Count == 0)
                {
                    try
                    {
                        fileItem.ReadFileAsByteList();
                    }
                    catch (Exception ex)
                    {
                        WriteError($"Failed to read encrypted file: {ex.Message}");
                        return;
                    }
                }

                // Verify we have data to decrypt
                if (fileItem.Data == null || fileItem.Data.Count == 0)
                {
                    WriteError("No data to decrypt - file may be empty or corrupted");
                    return;
                }

                try
                {
                    var result = await Task.Run(() => FileSealer.UnsealFile(fileItem.Data, currentPassword));
                    var decryptedData = result.data;
                    var metadata = result.metadata;

                    if (decryptedData == null || decryptedData.Count == 0)
                    {
                        WriteError("Decryption failed: Incorrect password or corrupted data");
                        return;
                    }

                    // Create the target path using the original name and extension
                    string directory = Path.GetDirectoryName(targetPath);
                    decryptedPath = Path.Combine(directory, metadata.OriginalName + metadata.Extension);

                    // Write the decrypted data to a temporary file first
                    string tempPath = decryptedPath + ".temp";
                    await File.WriteAllBytesAsync(tempPath, decryptedData.ToArray());

                    // Verify the decrypted file was written successfully
                    if (!File.Exists(tempPath))
                    {
                        WriteError("Failed to create decrypted file");
                        return;
                    }

                    var decryptedFileInfo = new FileInfo(tempPath);
                    if (decryptedFileInfo.Length == 0)
                    {
                        WriteError("Decrypted file is empty");
                        File.Delete(tempPath);
                        return;
                    }

                    // If we got here, decryption was successful
                    // Now we can safely move the temp file to the final location
                    if (File.Exists(decryptedPath))
                    {
                        File.Delete(decryptedPath);
                    }
                    File.Move(tempPath, decryptedPath);

                    // Only after successful decryption and verification, delete the encrypted file
                    if (File.Exists(encryptedPath))
                    {
                        File.Delete(encryptedPath);
                    }

                    WriteSuccess($"  Successfully decrypted {fileItem.FileName} to {Path.GetFileName(decryptedPath)}");
                }
                catch (Exception ex)
                {
                    WriteError($"  Decryption failed for {fileItem.FileName}: {ex.Message}");
                    Logger.LogError($"Decryption failed: {ex.Message}", fileItem);

                    // Clean up any temporary files
                    if (decryptedPath != null && File.Exists(decryptedPath))
                    {
                        try { File.Delete(decryptedPath); WriteInfo("  Cleaned up partial decrypted file."); }
                        catch { }
                    }
                }
            }
            catch (Exception ex)
            {
                WriteError($"  Decryption failed for {fileItem.FileName}: {ex.Message}");
                Logger.LogError($"Decryption failed: {ex.Message}", fileItem);

                // Clean up any temporary files
                if (decryptedPath != null && File.Exists(decryptedPath))
                {
                    try { File.Delete(decryptedPath); WriteInfo("  Cleaned up partial decrypted file."); }
                    catch { }
                }
            }
        }

        /// <summary>
        /// Reads a password from the console securely (masking input).
        /// </summary>
        private static string ReadPassword()
        {
            var password = new System.Text.StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    break;
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Length--;
                        Console.Write("\b \b");
                    }
                }
                else if (!char.IsControl(key.KeyChar)) // Ignore control keys except backspace/enter
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            string result = password.ToString();
            // WARNING: Logging password bytes is a security risk. Only for deep debugging.
            // WriteInfo($"DEBUG - Read password length: {result.Length}");
            // WriteInfo($"DEBUG - Read password bytes: {string.Join(",", Encoding.UTF8.GetBytes(result).Select(b => b.ToString("X2")))}");
            return result;
        }

        #region Console Writing Helpers
        private static void WriteHeader(string text)
        {
            lock (consoleLock)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("\n══════════════════════════════════════════════════════════════");
                Console.WriteLine($"  {text}");
                Console.WriteLine("══════════════════════════════════════════════════════════════");
                Console.ResetColor();
            }
        }

        private static void WriteMenu(string text)
        {
            lock (consoleLock)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($"  {text}");
                Console.ResetColor();
            }
        }

        private static void WriteInfo(string text)
        {
            lock (consoleLock)
            {
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write($"  {text}");
                Console.ResetColor();
            }
        }

        private static void WriteSuccess(string text)
        {
            lock (consoleLock)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine($"  ✓ {text}");
                Console.ResetColor();
            }
        }

        private static void WriteWarning(string text)
        {
            lock (consoleLock)
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine($"  ⚠ {text}");
                Console.ResetColor();
            }
        }

        private static void WriteError(string text)
        {
            lock (consoleLock)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine($"  ✗ {text}");
                Console.ResetColor();
            }
        }

        private static void ShowFooter()
        {
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("\n──────────────────────────────────────────────────────────────");
            Console.WriteLine("  Made with ❤️  by Hasan Aslan  |  github.com/itshasanaslan");
            Console.ResetColor();
        }
        #endregion

        /// <summary>
        /// Handles changing the user's password.
        /// </summary>
        private static async Task ChangePassword()
        {
            WriteHeader("Change Password");
            WriteInfo("Enter current password: ");
            string currentPasswordAttempt = ReadPassword();

            try
            {
                if (currentPasswordAttempt != GetPassword())
                {
                    WriteError("Current password is incorrect! Password not changed.");
                    Logger.LogWarning("Failed password change attempt: Incorrect current password.");
                    return;
                }
            }
            catch (Exception ex)
            {
                WriteError($"Error validating current password: {ex.Message}");
                Logger.LogError($"Error validating current password: {ex.Message}");
                return;
            }

            WriteInfo("Enter new password (5-20 characters): ");
            string newPassword = ReadPassword();
            
            if (newPassword.Length < 5 || newPassword.Length > 20)
            {
                WriteError("Password must be between 5 and 20 characters long.");
                return;
            }

            WriteInfo("Confirm new password: ");
            string confirmPassword = ReadPassword();

            if (newPassword != confirmPassword)
            {
                WriteError("New passwords do not match! Password not changed.");
                return;
            }

            SetPassword(newPassword);
            try
            {
                PasswordManager.SavePassword(newPassword);
                WriteSuccess("Password changed and hint saved successfully!");
                Logger.LogInfo("Password changed successfully.");
            }
            catch (Exception ex)
            {
                WriteWarning($"Password changed, but could not save hint: {ex.Message}");
                Logger.LogWarning($"Password changed, but hint save failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Displays the stored password hint.
        /// </summary>
        private static void ShowPasswordHint()
        {
            WriteHeader("Password Hint");
            try
            {
                string hint = PasswordManager.GetPasswordHint();
                WriteInfo(hint + "\n");
            }
            catch (Exception ex)
            {
                WriteError($"Error retrieving password hint: {ex.Message}");
                Logger.LogError($"Error retrieving password hint: {ex.Message}");
            }
        }

        /// <summary>
        /// Gets the current password in a thread-safe manner.
        /// </summary>
        private static string GetPassword()
        {
            lock (passwordLock)
            {
                // WARNING: Logging password info is a security risk.
                // if (!string.IsNullOrEmpty(password))
                // {
                //    Console.WriteLine($"DEBUG: GetPassword - Length: {password.Length}");
                // }
                return currentPassword;
            }
        }

        /// <summary>
        /// Sets the current password in a thread-safe manner.
        /// </summary>
        private static void SetPassword(string newPassword)
        {
            lock (passwordLock)
            {
                if (string.IsNullOrEmpty(newPassword))
                {
                    WriteError("Cannot set an empty password.");
                    return;
                }

                if (newPassword.Length < 5 || newPassword.Length > 20)
                {
                    WriteError("Password must be between 5 and 20 characters long.");
                    return;
                }

                currentPassword = newPassword;
                WriteSuccess($"Password set/updated.");
            }
        }

        /// <summary>
        /// Runs a self-test by creating, encrypting, and decrypting a file.
        /// </summary>
        private static async Task TestEncryptionDecryption()
        {
            WriteHeader("Test Encryption/Decryption");
            WriteInfo("Enter a temporary password for this test: ");
            string testPassword = ReadPassword();
            string originalPassword = GetPassword(); // Save original password
            SetPassword(testPassword); // Set test password

            string testFilePath = Path.Combine(Directory.GetCurrentDirectory(), "AEF2025_TestFile.txt");
            string encryptedPath = testFilePath + ".aslan";
            string decryptedPath = testFilePath; // It will decrypt to original name
            string testContent = $"This is a test file created at {DateTime.Now} for AEF2025 testing.";

            try
            {
                // 1. Create Test File
                WriteInfo($"\n1. Creating test file: {Path.GetFileName(testFilePath)}...");
                await File.WriteAllTextAsync(testFilePath, testContent);
                if (!File.Exists(testFilePath) || string.IsNullOrEmpty(await File.ReadAllTextAsync(testFilePath)))
                    throw new Exception("Failed to create or write to test file.");
                WriteSuccess("   Test file created.");

                // 2. Encrypt Test File
                WriteInfo($"\n2. Encrypting test file...");
                var fileItem = new FileItem(testFilePath);
                await EncryptFile(fileItem, encryptedPath); // EncryptFile now handles deletion
                if (!File.Exists(encryptedPath))
                    throw new Exception("Encrypted file was not created.");
                if (File.Exists(testFilePath))
                    throw new Exception("Original test file was not deleted after encryption.");
                WriteSuccess("   Test file encrypted successfully.");

                // 3. Decrypt Test File
                WriteInfo($"\n3. Decrypting test file...");
                var encryptedItem = new FileItem(encryptedPath);
                await DecryptFile(encryptedItem, decryptedPath); // DecryptFile now handles deletion
                if (!File.Exists(decryptedPath))
                    throw new Exception("Decrypted file was not created.");
                if (File.Exists(encryptedPath))
                    throw new Exception("Encrypted file was not deleted after decryption.");
                WriteSuccess("   Test file decrypted successfully.");

                // 4. Verify Content
                WriteInfo($"\n4. Verifying content...");
                string decryptedContent = await File.ReadAllTextAsync(decryptedPath);
                if (testContent == decryptedContent)
                {
                    WriteSuccess("   Content verification successful! Test Passed.");
                    Logger.LogInfo("Self-test passed successfully.");
                }
                else
                {
                    WriteError("   Content verification FAILED! Test Failed.");
                    WriteError($"   Original:  '{testContent}'");
                    WriteError($"   Decrypted: '{decryptedContent}'");
                    Logger.LogError("Self-test FAILED: Content mismatch.");
                }
            }
            catch (Exception ex)
            {
                WriteError($"\n--- Test FAILED ---");
                WriteError($"   Error: {ex.Message}");
                Logger.LogError($"Self-test FAILED: {ex.Message}");
            }
            finally
            {
                // Cleanup
                WriteInfo("\nCleaning up test files...");
                try { if (File.Exists(testFilePath)) File.Delete(testFilePath); } catch { }
                try { if (File.Exists(encryptedPath)) File.Delete(encryptedPath); } catch { }
                WriteInfo("   Cleanup finished.");
                SetPassword(originalPassword); // Restore original password
                WriteInfo("Original password restored.");
            }
        }

        private static async Task ProcessFilesWithProgress(List<string> files, bool isEncryption)
        {
            var stopwatch = Stopwatch.StartNew();
            var tasks = new List<Task>();
            var cts = new CancellationTokenSource();
            int processedCount = 0;
            int errorCount = 0;
            int totalFiles = files.Count;

            // Start a task to listen for cancellation key
            var cancellationTask = Task.Run(() =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    if (Console.KeyAvailable && Console.ReadKey(true).Key == ConsoleKey.Escape)
                    {
                        WriteWarning("\nCancellation requested! Waiting for current tasks to finish...");
                        cts.Cancel();
                        break;
                    }
                    Thread.Sleep(100);
                }
            });

            foreach (var file in files)
            {
                if (cts.Token.IsCancellationRequested)
                {
                    WriteWarning("Operation cancelled.");
                    break;
                }

                try
                {
                    await semaphore.WaitAsync(cts.Token);
                    tasks.Add(Task.Run(async () =>
                    {
                        try
                        {
                            await ProcessFile(file, isEncryption);
                            Interlocked.Increment(ref processedCount);
                            UpdateProgress(processedCount, errorCount, totalFiles);
                        }
                        catch (Exception ex)
                        {
                            Interlocked.Increment(ref errorCount);
                            WriteError($"Error processing {Path.GetFileName(file)}: {ex.Message}");
                            Logger.LogError($"Error processing {file}: {ex.Message}");
                        }
                        finally
                        {
                            semaphore.Release();
                        }
                    }, cts.Token));
                }
                catch (Exception ex)
                {
                    WriteError($"Error queuing file {Path.GetFileName(file)}: {ex.Message}");
                    Logger.LogError($"Error queuing {file}: {ex.Message}");
                }
            }

            try
            {
                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException)
            {
                WriteWarning("Some tasks may have been cancelled.");
            }
            finally
            {
                if (!cts.IsCancellationRequested) cts.Cancel();
                await cancellationTask;
            }

            stopwatch.Stop();
            ShowOperationSummary(processedCount, errorCount, stopwatch.Elapsed);
        }

        private static void UpdateProgress(int processed, int errors, int total)
        {
            double percentage = (double)processed / total * 100;
            Console.Write($"\r  Progress: [{new string('█', (int)(percentage / 2))}{new string('░', 50 - (int)(percentage / 2))}] {percentage:F1}% ({processed}/{total} files, {errors} errors)");
        }

        private static void ShowOperationSummary(int processed, int errors, TimeSpan duration)
        {
            WriteHeader("Operation Summary");
            WriteSuccess($"Completed in {duration.TotalSeconds:F2} seconds");
            WriteSuccess($"Successfully processed: {processed} files");
            if (errors > 0)
            {
                WriteError($"Failed to process: {errors} files (Check logs for details)");
            }
            else
            {
                WriteSuccess("All files processed without errors");
            }
            Logger.LogInfo($"Operation completed: {processed} success, {errors} errors. Duration: {duration.TotalSeconds:F2}s.");
        }
    }
}