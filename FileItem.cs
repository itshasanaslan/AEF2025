using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Security.Cryptography;

namespace AEF2025
{
    /// <summary>
    /// Represents a file item with its metadata and data content.
    /// This class handles file operations including reading, writing, and metadata management.
    /// </summary>
    public class FileItem
    {
        /// <summary>
        /// Gets or sets the full path of the file.
        /// </summary>
        public string FullPath { get; set; }

        /// <summary>
        /// Gets or sets the name of the file including extension.
        /// </summary>
        public string FileName { get; set; }

        /// <summary>
        /// Gets or sets the name of the file without extension.
        /// </summary>
        public string Name { get; set; }

        /// <summary>
        /// Gets or sets the original name of the file before encryption.
        /// </summary>
        public string OriginalName { get; set; }

        /// <summary>
        /// Gets or sets the file extension.
        /// </summary>
        public string Extension { get; set; }

        /// <summary>
        /// Gets or sets the file creation time.
        /// </summary>
        public DateTime CreationTime { get; set; }

        /// <summary>
        /// Gets or sets the last write time of the file.
        /// </summary>
        public DateTime LastWriteTime { get; set; }

        /// <summary>
        /// Gets or sets the last access time of the file.
        /// </summary>
        public DateTime LastAccessTime { get; set; }

        /// <summary>
        /// Gets or sets the file attributes.
        /// </summary>
        public FileAttributes Attributes { get; set; }

        /// <summary>
        /// Gets or sets the size of the file in bytes.
        /// </summary>
        public long FileSize { get; set; }

        /// <summary>
        /// Gets or sets whether the file is read-only.
        /// </summary>
        public bool IsReadOnly { get; set; }

        /// <summary>
        /// Gets or sets the file data as a list of bytes.
        /// </summary>
        public List<byte> Data { get; set; }

        /// <summary>
        /// The buffer size used for reading files (1MB).
        /// </summary>
        public const int BUFFER_SIZE = 1024 * 1024; // 1MB buffer

        /// <summary>
        /// Gets the original filename and extension as bytes.
        /// </summary>
        /// <returns>A byte array containing the filename and extension.</returns>
        public byte[] GetOriginalNameAsBytes()
        {
            // Format: [filename length (4 bytes)][filename][extension length (4 bytes)][extension]
            using (MemoryStream ms = new MemoryStream())
            using (BinaryWriter writer = new BinaryWriter(ms))
            {
                // Write filename length and filename
                byte[] nameBytes = Encoding.UTF8.GetBytes(Name);
                writer.Write(nameBytes.Length);
                writer.Write(nameBytes);

                // Write extension length and extension
                byte[] extBytes = Encoding.UTF8.GetBytes(Extension);
                writer.Write(extBytes.Length);
                writer.Write(extBytes);

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Sets the filename and extension from bytes.
        /// </summary>
        /// <param name="bytes">The byte array containing the filename and extension.</param>
        /// <exception cref="ArgumentException">Thrown when the byte array is invalid.</exception>
        public void SetNameFromBytes(byte[] bytes)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream(bytes))
                using (BinaryReader reader = new BinaryReader(ms))
                {
                    // Read filename
                    int nameLength = reader.ReadInt32();
                    byte[] nameBytes = reader.ReadBytes(nameLength);
                    Name = Encoding.UTF8.GetString(nameBytes);

                    // Read extension
                    int extLength = reader.ReadInt32();
                    byte[] extBytes = reader.ReadBytes(extLength);
                    Extension = Encoding.UTF8.GetString(extBytes);

                    // Update FileName
                    FileName = Name + Extension;
                }
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Invalid byte array format for filename and extension", ex);
            }
        }

        /// <summary>
        /// Gets the size of the original name data in bytes.
        /// </summary>
        /// <returns>The size in bytes.</returns>
        public int GetOriginalNameSize()
        {
            return GetOriginalNameAsBytes().Length;
        }

        /// <summary>
        /// Initializes a new instance of the FileItem class with the specified file path.
        /// </summary>
        /// <param name="path">The full path to the file.</param>
        /// <exception cref="ArgumentException">Thrown when the path is null or empty.</exception>
        /// <exception cref="Exception">Thrown when there is an error accessing file metadata.</exception>
        public FileItem(string path)
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentException("Path cannot be null or empty", nameof(path));

            FullPath = path;
            FileName = Path.GetFileName(path);
            Name = Path.GetFileNameWithoutExtension(path);
            Extension = Path.GetExtension(path);
            Data = new List<byte>();

            try
            {
                var fileInfo = new FileInfo(path);
                if (fileInfo.Exists)
                {
                    CreationTime = fileInfo.CreationTime;
                    LastWriteTime = fileInfo.LastWriteTime;
                    LastAccessTime = fileInfo.LastAccessTime;
                    Attributes = fileInfo.Attributes;
                    FileSize = fileInfo.Length;
                    IsReadOnly = fileInfo.IsReadOnly;
                }
                else
                {
                    // Set default values if file doesn't exist
                    CreationTime = DateTime.Now;
                    LastWriteTime = DateTime.Now;
                    LastAccessTime = DateTime.Now;
                    Attributes = FileAttributes.Normal;
                    FileSize = 0;
                    IsReadOnly = false;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error accessing file metadata: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Reads the file content into a list of bytes.
        /// </summary>
        /// <returns>A list of bytes containing the file data.</returns>
        /// <exception cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
        /// <exception cref="Exception">Thrown when there is an error reading the file.</exception>
        public List<byte> ReadFileAsByteList()
        {
            try
            {
                // Validate path
                if (string.IsNullOrEmpty(FullPath))
                {
                    throw new ArgumentException("File path is null or empty");
                }

                // Check if file exists
                if (!File.Exists(FullPath))
                {
                    throw new FileNotFoundException($"File not found: {FullPath}");
                }

                // Check file attributes and permissions
                var fileInfo = new FileInfo(FullPath);
                if (fileInfo.Length == 0)
                {
                    throw new Exception("File is empty");
                }

                // Initialize Data list with capacity to avoid resizing
                Data = new List<byte>((int)fileInfo.Length);

                try
                {
                    // Read the file in chunks to handle large files
                    using (FileStream fs = new FileStream(FullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytesRead;
                        long totalBytesRead = 0;
                        long fileSize = fileInfo.Length;

                        while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                        {
                            Data.AddRange(buffer.Take(bytesRead));
                            totalBytesRead += bytesRead;

                            // Optional: Report progress for large files
                            if (fileSize > 100 * 1024 * 1024) // If file is larger than 100MB
                            {
                                double progress = (double)totalBytesRead / fileSize * 100;
                                Console.Write($"\rReading file: {progress:F1}% complete");
                            }
                        }
                        if (fileSize > 100 * 1024 * 1024)
                        {
                            Console.WriteLine(); // New line after progress
                        }
                    }

                    if (Data.Count == 0)
                    {
                        throw new Exception("No data was read from the file");
                    }

                    return Data;
                }
                catch (UnauthorizedAccessException)
                {
                    throw new Exception($"Access denied to file: {FullPath}");
                }
                catch (IOException ex)
                {
                    throw new Exception($"I/O error reading file: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error reading file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Asynchronously reads the file content into a list of bytes.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation. The task result contains the list of bytes.</returns>
        /// <exception cref="ArgumentException">Thrown when the file path is null or empty.</exception>
        /// <exception cref="FileNotFoundException">Thrown when the file does not exist.</exception>
        /// <exception cref="Exception">Thrown when there is an error reading the file.</exception>
        public async Task<List<byte>> ReadFileAsByteListAsync()
        {
            try
            {
                // Validate path
                if (string.IsNullOrEmpty(FullPath))
                {
                    throw new ArgumentException("File path is null or empty");
                }

                // Check if file exists
                if (!File.Exists(FullPath))
                {
                    throw new FileNotFoundException($"File not found: {FullPath}");
                }

                // Check file attributes and permissions
                var fileInfo = new FileInfo(FullPath);
                if (fileInfo.Length == 0)
                {
                    throw new Exception("File is empty");
                }

                // Initialize Data list with capacity to avoid resizing
                Data = new List<byte>((int)fileInfo.Length);

                try
                {
                    // Read the file in chunks to handle large files
                    using (FileStream fs = new FileStream(FullPath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        byte[] buffer = new byte[BUFFER_SIZE];
                        int bytesRead;
                        long totalBytesRead = 0;
                        long fileSize = fileInfo.Length;

                        while ((bytesRead = await fs.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            Data.AddRange(buffer.Take(bytesRead));
                            totalBytesRead += bytesRead;

                            // Optional: Report progress for large files
                            if (fileSize > 100 * 1024 * 1024) // If file is larger than 100MB
                            {
                                double progress = (double)totalBytesRead / fileSize * 100;
                                Console.Write($"\rReading file: {progress:F1}% complete");
                            }
                        }
                        if (fileSize > 100 * 1024 * 1024)
                        {
                            Console.WriteLine(); // New line after progress
                        }
                    }

                    if (Data.Count == 0)
                    {
                        throw new Exception("No data was read from the file");
                    }

                    return Data;
                }
                catch (UnauthorizedAccessException)
                {
                    throw new Exception($"Access denied to file: {FullPath}");
                }
                catch (IOException ex)
                {
                    throw new Exception($"I/O error reading file: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error reading file: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Restores the file metadata to the specified target path.
        /// </summary>
        /// <param name="targetPath">The path where the metadata should be restored.</param>
        /// <exception cref="Exception">Thrown when there is an error restoring the metadata.</exception>
        public void RestoreFileMetadata(string targetPath)
        {
            try
            {
                var fileInfo = new FileInfo(targetPath);
                if (fileInfo.Exists)
                {
                    fileInfo.CreationTime = CreationTime;
                    fileInfo.LastWriteTime = LastWriteTime;
                    fileInfo.LastAccessTime = LastAccessTime;
                    fileInfo.Attributes = Attributes;
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error restoring file metadata: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Prints the file metadata to the console.
        /// </summary>
        public void PrintMetadata()
        {
            Console.WriteLine($"File Path: {FullPath}");
            Console.WriteLine($"File Name: {FileName}");
            Console.WriteLine($"Name without extension: {Name}");
            Console.WriteLine($"Directory: {Path.GetDirectoryName(FullPath)}");
            Console.WriteLine($"File Size: {FileSize} bytes");
            Console.WriteLine($"Creation Time: {CreationTime}");
            Console.WriteLine($"Last Access Time: {LastAccessTime}");
            Console.WriteLine($"Last Write Time: {LastWriteTime}");
            Console.WriteLine($"Attributes: {Attributes}");
            Console.WriteLine($"Is Read-Only: {IsReadOnly}");
            Console.WriteLine($"Extension: {Extension}");
        }

        /// <summary>
        /// Generates a random filename for encryption.
        /// </summary>
        /// <returns>A random filename with .aslan extension.</returns>
        private string GenerateRandomEncryptedName()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                byte[] randomBytes = new byte[16];
                rng.GetBytes(randomBytes);
                return Convert.ToBase64String(randomBytes).Replace("/", "_").Replace("+", "-").Substring(0, 16) + ".aslan";
            }
        }

        /// <summary>
        /// Generates a new random name for encryption without moving the file.
        /// </summary>
        /// <returns>The new file path.</returns>
        /// <exception cref="Exception">Thrown when there is an error generating the new name.</exception>
        public string GenerateEncryptedName()
        {
            try
            {
                // Store original name and extension before any operations
                OriginalName = Name;
                
                // Read the file data before any operations
                if (Data == null || Data.Count == 0)
                {
                    ReadFileAsByteList();
                }

                string directory = Path.GetDirectoryName(FullPath);
                string newFileName = GenerateRandomEncryptedName();
                string newPath = Path.Combine(directory, newFileName);

                // Update the properties for the new path
                FileName = newFileName;
                Name = Path.GetFileNameWithoutExtension(newFileName);
                Extension = ".aslan";

                return newPath;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error generating encrypted name: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Restores the original filename and extension after decryption.
        /// </summary>
        /// <param name="originalNameData">The byte array containing the original name data.</param>
        /// <returns>The restored file path.</returns>
        /// <exception cref="Exception">Thrown when there is an error restoring the original filename.</exception>
        public string RestoreOriginalName(byte[] originalNameData)
        {
            try
            {
                // First set the original name from the data
                SetNameFromBytes(originalNameData);

                string directory = Path.GetDirectoryName(FullPath);
                string originalPath = Path.Combine(directory, FileName);

                // If the file exists, rename it
                if (File.Exists(FullPath))
                {
                    File.Move(FullPath, originalPath);
                }

                // Update the properties
                FullPath = originalPath;

                return originalPath;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error restoring original filename: {ex.Message}", ex);
            }
        }
    }
}