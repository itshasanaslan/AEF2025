using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AEF2025
{
    /// <summary>
    /// Provides encryption and decryption operations for files and data.
    /// This class handles the core cryptographic operations of the application.
    /// </summary>
    public class Operator
    {
        /// <summary>
        /// The size of the salt used in key derivation (in bytes).
        /// </summary>
        private const int SALT_SIZE = 16;

        /// <summary>
        /// The number of iterations used in key derivation.
        /// </summary>
        private const int ITERATIONS = 100000;

        /// <summary>
        /// The size of the key used for encryption (in bytes).
        /// </summary>
        private const int KEY_SIZE = 32;

        /// <summary>
        /// The size of the initialization vector (in bytes).
        /// </summary>
        private const int IV_SIZE = 16;

        /// <summary>
        /// The size of the authentication tag (in bytes).
        /// </summary>
        private const int TAG_SIZE = 16;

        /// <summary>
        /// The size of the metadata header (in bytes).
        /// </summary>
        private const int METADATA_HEADER_SIZE = 4;

        /// <summary>
        /// The size of the file size field in the metadata (in bytes).
        /// </summary>
        private const int FILE_SIZE_FIELD_SIZE = 8;

        /// <summary>
        /// The size of the creation time field in the metadata (in bytes).
        /// </summary>
        private const int CREATION_TIME_FIELD_SIZE = 8;

        /// <summary>
        /// The size of the last write time field in the metadata (in bytes).
        /// </summary>
        private const int LAST_WRITE_TIME_FIELD_SIZE = 8;

        /// <summary>
        /// The size of the last access time field in the metadata (in bytes).
        /// </summary>
        private const int LAST_ACCESS_TIME_FIELD_SIZE = 8;

        /// <summary>
        /// The size of the attributes field in the metadata (in bytes).
        /// </summary>
        private const int ATTRIBUTES_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the is read-only field in the metadata (in bytes).
        /// </summary>
        private const int IS_READ_ONLY_FIELD_SIZE = 1;

        /// <summary>
        /// The size of the extension length field in the metadata (in bytes).
        /// </summary>
        private const int EXTENSION_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the name length field in the metadata (in bytes).
        /// </summary>
        private const int NAME_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the file name length field in the metadata (in bytes).
        /// </summary>
        private const int FILE_NAME_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the full path length field in the metadata (in bytes).
        /// </summary>
        private const int FULL_PATH_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the metadata length field (in bytes).
        /// </summary>
        private const int METADATA_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the data length field (in bytes).
        /// </summary>
        private const int DATA_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the tag length field (in bytes).
        /// </summary>
        private const int TAG_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the IV length field (in bytes).
        /// </summary>
        private const int IV_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the salt length field (in bytes).
        /// </summary>
        private const int SALT_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the iterations field (in bytes).
        /// </summary>
        private const int ITERATIONS_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the key length field (in bytes).
        /// </summary>
        private const int KEY_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the version field (in bytes).
        /// </summary>
        private const int VERSION_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the header length field (in bytes).
        /// </summary>
        private const int HEADER_LENGTH_FIELD_SIZE = 4;

        /// <summary>
        /// The size of the header (in bytes).
        /// </summary>
        private const int HEADER_SIZE = HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE + ITERATIONS_FIELD_SIZE + SALT_LENGTH_FIELD_SIZE + IV_LENGTH_FIELD_SIZE + TAG_LENGTH_FIELD_SIZE + DATA_LENGTH_FIELD_SIZE + METADATA_LENGTH_FIELD_SIZE;

        /// <summary>
        /// The version of the encryption format.
        /// </summary>
        private const int VERSION = 1;

        /// <summary>
        /// Initializes a new instance of the Operator class.
        /// </summary>
        public Operator()
        {
        }

        /// <summary>
        /// Seals a file with encryption and metadata.
        /// </summary>
        /// <param name="item">The file item to seal.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <returns>A list of bytes containing the sealed data.</returns>
        /// <exception cref="Exception">Thrown when there is an error during the sealing process.</exception>
        public List<byte> SealFile(FileItem item, string password)
        {
            try
            {
                if (item == null)
                {
                    throw new ArgumentNullException(nameof(item), "FileItem cannot be null");
                }

                if (string.IsNullOrEmpty(password))
                {
                    throw new ArgumentException("Password cannot be null or empty", nameof(password));
                }

                // Ensure file data is read
                if (item.Data == null)
                {
                    try
                    {
                        item.ReadFileAsByteList();
                    }
                    catch (Exception ex)
                    {
                        throw new Exception($"Failed to read file data: {ex.Message}", ex);
                    }
                }

                if (item.Data == null)
                {
                    throw new Exception("File data is null after reading attempt");
                }

                if (item.Data.Count == 0)
                {
                    throw new Exception($"File is empty: {item.FullPath}");
                }

                // Create metadata object
                var metadata = new FileMetadata
                {
                    OriginalName = item.Name,
                    Extension = item.Extension,
                    CreationTime = item.CreationTime,
                    LastAccessTime = item.LastAccessTime,
                    LastWriteTime = item.LastWriteTime,
                    Attributes = item.Attributes
                };

                // Serialize metadata to JSON
                string metadataJson = JsonSerializer.Serialize(metadata);
                byte[] metadataBytes = Encoding.UTF8.GetBytes(metadataJson);
                byte[] metadataLengthBytes = BitConverter.GetBytes(metadataBytes.Length);

                // Generate a random salt
                byte[] salt = new byte[SALT_SIZE];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(salt);
                }

                // Generate key from password using PBKDF2
                byte[] key = GenerateKeyFromPassword(password, salt);

                // Generate a random IV for AES
                byte[] iv = new byte[16];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(iv);
                }

                // Encrypt the file data
                byte[] encryptedData;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(item.Data.ToArray(), 0, item.Data.Count);
                            cs.FlushFinalBlock();
                        }
                        encryptedData = ms.ToArray();
                    }
                }

                if (encryptedData == null || encryptedData.Length == 0)
                {
                    throw new Exception("Encryption produced no data");
                }

                // Combine all components
                List<byte> sealedData = new List<byte>();
                sealedData.AddRange(salt); // 16 bytes
                sealedData.AddRange(iv);   // 16 bytes
                sealedData.AddRange(metadataLengthBytes); // 4 bytes
                sealedData.AddRange(metadataBytes); // metadata
                sealedData.AddRange(encryptedData); // encrypted file data

                if (sealedData.Count == 0)
                {
                    throw new Exception("Final sealed data is empty");
                }

                return sealedData;
            }
            catch (Exception ex)
            {
                throw new Exception($"Encryption failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Unseals a file from its encrypted format.
        /// </summary>
        /// <param name="sealedData">The sealed data to unseal.</param>
        /// <param name="password">The password to use for decryption.</param>
        /// <returns>A tuple containing the decrypted data and the file item with metadata.</returns>
        /// <exception cref="Exception">Thrown when there is an error during the unsealing process.</exception>
        public (List<byte> Data, FileItem Item) UnsealFile(List<byte> sealedData, string password)
        {
            try
            {
                // Read header
                var headerSize = BitConverter.ToInt32(sealedData.Take(HEADER_LENGTH_FIELD_SIZE).ToArray(), 0);
                var version = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE).Take(VERSION_FIELD_SIZE).ToArray(), 0);
                var keySize = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE).Take(KEY_LENGTH_FIELD_SIZE).ToArray(), 0);
                var iterations = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE).Take(ITERATIONS_FIELD_SIZE).ToArray(), 0);
                var saltSize = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE + ITERATIONS_FIELD_SIZE).Take(SALT_LENGTH_FIELD_SIZE).ToArray(), 0);
                var ivSize = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE + ITERATIONS_FIELD_SIZE + SALT_LENGTH_FIELD_SIZE).Take(IV_LENGTH_FIELD_SIZE).ToArray(), 0);
                var tagSize = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE + ITERATIONS_FIELD_SIZE + SALT_LENGTH_FIELD_SIZE + IV_LENGTH_FIELD_SIZE).Take(TAG_LENGTH_FIELD_SIZE).ToArray(), 0);
                var dataSize = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE + ITERATIONS_FIELD_SIZE + SALT_LENGTH_FIELD_SIZE + IV_LENGTH_FIELD_SIZE + TAG_LENGTH_FIELD_SIZE).Take(DATA_LENGTH_FIELD_SIZE).ToArray(), 0);
                var metadataSize = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE + ITERATIONS_FIELD_SIZE + SALT_LENGTH_FIELD_SIZE + IV_LENGTH_FIELD_SIZE + TAG_LENGTH_FIELD_SIZE + DATA_LENGTH_FIELD_SIZE).Take(METADATA_LENGTH_FIELD_SIZE).ToArray(), 0);
                var originalNameSize = BitConverter.ToInt32(sealedData.Skip(HEADER_LENGTH_FIELD_SIZE + VERSION_FIELD_SIZE + KEY_LENGTH_FIELD_SIZE + ITERATIONS_FIELD_SIZE + SALT_LENGTH_FIELD_SIZE + IV_LENGTH_FIELD_SIZE + TAG_LENGTH_FIELD_SIZE + DATA_LENGTH_FIELD_SIZE + METADATA_LENGTH_FIELD_SIZE).Take(4).ToArray(), 0);

                // Validate version
                if (version != VERSION)
                {
                    throw new Exception($"Unsupported version: {version}");
                }

                // Extract components
                var salt = sealedData.Skip(HEADER_SIZE).Take(saltSize).ToList();
                var iv = sealedData.Skip(HEADER_SIZE + saltSize).Take(ivSize).ToList();
                var tag = sealedData.Skip(HEADER_SIZE + saltSize + ivSize).Take(tagSize).ToList();
                var encryptedData = sealedData.Skip(HEADER_SIZE + saltSize + ivSize + tagSize).Take(dataSize).ToList();
                var metadata = sealedData.Skip(HEADER_SIZE + saltSize + ivSize + tagSize + dataSize).Take(metadataSize).ToList();
                var originalNameData = sealedData.Skip(HEADER_SIZE + saltSize + ivSize + tagSize + dataSize + metadataSize).Take(originalNameSize).ToList();

                // Decrypt data
                var decryptedData = DecryptData(encryptedData, password, salt, iv, tag);

                // Parse metadata
                var fileMetadata = ParseMetadata(metadata);

                // Restore original name
                fileMetadata.OriginalName = Encoding.UTF8.GetString(originalNameData.Take(originalNameData.Count - 4).ToArray());
                fileMetadata.Extension = Encoding.UTF8.GetString(originalNameData.Skip(originalNameData.Count - 4).ToArray());

                return (decryptedData, fileMetadata);
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("Incorrect password or corrupted data"))
                {
                    // Do not throw, just return empty data to indicate failure
                    Logger.LogError("Decryption failed: Incorrect password or corrupted data.");
                    return (new List<byte>(), null);
                }
                Logger.LogError($"Decryption failed due to an unexpected error: {ex.Message}");
                return (new List<byte>(), null);
            }
        }

        /// <summary>
        /// Encrypts data using AES-GCM encryption.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="password">The password to use for encryption.</param>
        /// <returns>A list of bytes containing the encrypted data.</returns>
        /// <exception cref="Exception">Thrown when there is an error during encryption.</exception>
        private List<byte> EncryptData(List<byte> data, string password)
        {
            try
            {
                // Generate salt
                var salt = new byte[SALT_SIZE];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(salt);
                }

                // Generate key
                var key = new byte[KEY_SIZE];
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS))
                {
                    key = pbkdf2.GetBytes(KEY_SIZE);
                }

                // Generate IV
                var iv = new byte[IV_SIZE];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(iv);
                }

                // Encrypt data
                var encryptedData = new List<byte>();
                using (var aes = new AesGcm(key))
                {
                    var tag = new byte[TAG_SIZE];
                    var ciphertext = new byte[data.Count];
                    aes.Encrypt(iv, data.ToArray(), ciphertext, tag);

                    encryptedData.AddRange(salt);
                    encryptedData.AddRange(iv);
                    encryptedData.AddRange(tag);
                    encryptedData.AddRange(ciphertext);
                }

                return encryptedData;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error encrypting data: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Decrypts data using AES-GCM decryption.
        /// </summary>
        /// <param name="encryptedData">The encrypted data to decrypt.</param>
        /// <param name="password">The password to use for decryption.</param>
        /// <param name="salt">The salt used in encryption.</param>
        /// <param name="iv">The initialization vector used in encryption.</param>
        /// <param name="tag">The authentication tag used in encryption.</param>
        /// <returns>A list of bytes containing the decrypted data.</returns>
        /// <exception cref="Exception">Thrown when there is an error during decryption.</exception>
        private List<byte> DecryptData(List<byte> encryptedData, string password, List<byte> salt, List<byte> iv, List<byte> tag)
        {
            try
            {
                // Generate key
                var key = new byte[KEY_SIZE];
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt.ToArray(), ITERATIONS))
                {
                    key = pbkdf2.GetBytes(KEY_SIZE);
                }

                // Decrypt data
                var decryptedData = new List<byte>();
                using (var aes = new AesGcm(key))
                {
                    var plaintext = new byte[encryptedData.Count];
                    aes.Decrypt(iv.ToArray(), encryptedData.ToArray(), tag.ToArray(), plaintext);
                    decryptedData.AddRange(plaintext);
                }

                return decryptedData;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error decrypting data: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Generates metadata for a file item.
        /// </summary>
        /// <param name="item">The file item to generate metadata for.</param>
        /// <returns>A list of bytes containing the metadata.</returns>
        private List<byte> GenerateMetadata(FileItem item)
        {
            var metadata = new List<byte>();

            // Add metadata header
            metadata.AddRange(BitConverter.GetBytes(METADATA_HEADER_SIZE));

            // Add file size
            metadata.AddRange(BitConverter.GetBytes(item.FileSize));

            // Add creation time
            metadata.AddRange(BitConverter.GetBytes(item.CreationTime.ToBinary()));

            // Add last write time
            metadata.AddRange(BitConverter.GetBytes(item.LastWriteTime.ToBinary()));

            // Add last access time
            metadata.AddRange(BitConverter.GetBytes(item.LastAccessTime.ToBinary()));

            // Add attributes
            metadata.AddRange(BitConverter.GetBytes((int)item.Attributes));

            // Add is read-only
            metadata.AddRange(BitConverter.GetBytes(item.IsReadOnly));

            // Add extension
            var extensionBytes = Encoding.UTF8.GetBytes(item.Extension);
            metadata.AddRange(BitConverter.GetBytes(extensionBytes.Length));
            metadata.AddRange(extensionBytes);

            // Add name
            var nameBytes = Encoding.UTF8.GetBytes(item.Name);
            metadata.AddRange(BitConverter.GetBytes(nameBytes.Length));
            metadata.AddRange(nameBytes);

            // Add file name
            var fileNameBytes = Encoding.UTF8.GetBytes(item.FileName);
            metadata.AddRange(BitConverter.GetBytes(fileNameBytes.Length));
            metadata.AddRange(fileNameBytes);

            // Add full path
            var fullPathBytes = Encoding.UTF8.GetBytes(item.FullPath);
            metadata.AddRange(BitConverter.GetBytes(fullPathBytes.Length));
            metadata.AddRange(fullPathBytes);

            return metadata;
        }

        /// <summary>
        /// Parses metadata from a list of bytes.
        /// </summary>
        /// <param name="metadata">The metadata to parse.</param>
        /// <returns>A file item containing the parsed metadata.</returns>
        /// <exception cref="Exception">Thrown when there is an error parsing the metadata.</exception>
        private FileItem ParseMetadata(List<byte> metadata)
        {
            try
            {
                var offset = 0;

                // Read metadata header
                var metadataHeaderSize = BitConverter.ToInt32(metadata.Skip(offset).Take(METADATA_HEADER_SIZE).ToArray(), 0);
                offset += METADATA_HEADER_SIZE;

                // Read file size
                var fileSize = BitConverter.ToInt64(metadata.Skip(offset).Take(FILE_SIZE_FIELD_SIZE).ToArray(), 0);
                offset += FILE_SIZE_FIELD_SIZE;

                // Read creation time
                var creationTime = DateTime.FromBinary(BitConverter.ToInt64(metadata.Skip(offset).Take(CREATION_TIME_FIELD_SIZE).ToArray(), 0));
                offset += CREATION_TIME_FIELD_SIZE;

                // Read last write time
                var lastWriteTime = DateTime.FromBinary(BitConverter.ToInt64(metadata.Skip(offset).Take(LAST_WRITE_TIME_FIELD_SIZE).ToArray(), 0));
                offset += LAST_WRITE_TIME_FIELD_SIZE;

                // Read last access time
                var lastAccessTime = DateTime.FromBinary(BitConverter.ToInt64(metadata.Skip(offset).Take(LAST_ACCESS_TIME_FIELD_SIZE).ToArray(), 0));
                offset += LAST_ACCESS_TIME_FIELD_SIZE;

                // Read attributes
                var attributes = (FileAttributes)BitConverter.ToInt32(metadata.Skip(offset).Take(ATTRIBUTES_FIELD_SIZE).ToArray(), 0);
                offset += ATTRIBUTES_FIELD_SIZE;

                // Read is read-only
                var isReadOnly = BitConverter.ToBoolean(metadata.Skip(offset).Take(IS_READ_ONLY_FIELD_SIZE).ToArray(), 0);
                offset += IS_READ_ONLY_FIELD_SIZE;

                // Read extension
                var extensionLength = BitConverter.ToInt32(metadata.Skip(offset).Take(EXTENSION_LENGTH_FIELD_SIZE).ToArray(), 0);
                offset += EXTENSION_LENGTH_FIELD_SIZE;
                var extension = Encoding.UTF8.GetString(metadata.Skip(offset).Take(extensionLength).ToArray());
                offset += extensionLength;

                // Read name
                var nameLength = BitConverter.ToInt32(metadata.Skip(offset).Take(NAME_LENGTH_FIELD_SIZE).ToArray(), 0);
                offset += NAME_LENGTH_FIELD_SIZE;
                var name = Encoding.UTF8.GetString(metadata.Skip(offset).Take(nameLength).ToArray());
                offset += nameLength;

                // Read file name
                var fileNameLength = BitConverter.ToInt32(metadata.Skip(offset).Take(FILE_NAME_LENGTH_FIELD_SIZE).ToArray(), 0);
                offset += FILE_NAME_LENGTH_FIELD_SIZE;
                var fileName = Encoding.UTF8.GetString(metadata.Skip(offset).Take(fileNameLength).ToArray());
                offset += fileNameLength;

                // Read full path
                var fullPathLength = BitConverter.ToInt32(metadata.Skip(offset).Take(FULL_PATH_LENGTH_FIELD_SIZE).ToArray(), 0);
                offset += FULL_PATH_LENGTH_FIELD_SIZE;
                var fullPath = Encoding.UTF8.GetString(metadata.Skip(offset).Take(fullPathLength).ToArray());
                offset += fullPathLength;

                // Create file item
                var item = new FileItem(fullPath)
                {
                    FileName = fileName,
                    Name = name,
                    Extension = extension,
                    CreationTime = creationTime,
                    LastWriteTime = lastWriteTime,
                    LastAccessTime = lastAccessTime,
                    Attributes = attributes,
                    FileSize = fileSize,
                    IsReadOnly = isReadOnly
                };

                return item;
            }
            catch (Exception ex)
            {
                throw new Exception($"Error parsing metadata: {ex.Message}", ex);
            }
        }

        private static byte[] GenerateKeyFromPassword(string password, byte[] salt)
        {
            try
            {
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA256))
                {
                    return pbkdf2.GetBytes(KEY_SIZE);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error generating key: {ex.Message}", ex);
            }
        }
    }

    public class FileSealer
    {
        private static readonly int SALT_SIZE = 16; // 16 bytes for salt
        private static readonly int KEY_SIZE = 32; // 32 bytes for AES-256
        private static readonly int ITERATIONS = 100000; // Number of PBKDF2 iterations

        private static byte[] GenerateKeyFromPassword(string password, byte[] salt)
        {
            try
            {
                using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA256))
                {
                    return pbkdf2.GetBytes(KEY_SIZE);
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Error generating key: {ex.Message}", ex);
            }
        }

        public static List<byte> SealFile(FileItem item, string password)
        {
            try
            {
                if (item == null)
                {
                    throw new ArgumentNullException(nameof(item), "FileItem cannot be null");
                }

                if (string.IsNullOrEmpty(password))
                {
                    throw new ArgumentException("Password cannot be null or empty", nameof(password));
                }

                // Ensure file data is read
                if (item.Data == null)
                {
                    try
                    {
                        item.ReadFileAsByteList();
                    }
                    catch (Exception ex)
                    {
                        throw new Exception($"Failed to read file data: {ex.Message}", ex);
                    }
                }

                if (item.Data == null)
                {
                    throw new Exception("File data is null after reading attempt");
                }

                if (item.Data.Count == 0)
                {
                    throw new Exception($"File is empty: {item.FullPath}");
                }

                // Create metadata object
                var metadata = new FileMetadata
                {
                    OriginalName = item.Name,
                    Extension = item.Extension,
                    CreationTime = item.CreationTime,
                    LastAccessTime = item.LastAccessTime,
                    LastWriteTime = item.LastWriteTime,
                    Attributes = item.Attributes
                };

                // Serialize metadata to JSON
                string metadataJson = JsonSerializer.Serialize(metadata);
                byte[] metadataBytes = Encoding.UTF8.GetBytes(metadataJson);
                byte[] metadataLengthBytes = BitConverter.GetBytes(metadataBytes.Length);

                // Generate a random salt
                byte[] salt = new byte[SALT_SIZE];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(salt);
                }

                // Generate key from password using PBKDF2
                byte[] key = GenerateKeyFromPassword(password, salt);

                // Generate a random IV for AES
                byte[] iv = new byte[16];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(iv);
                }

                // Encrypt the file data
                byte[] encryptedData;
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(item.Data.ToArray(), 0, item.Data.Count);
                            cs.FlushFinalBlock();
                        }
                        encryptedData = ms.ToArray();
                    }
                }

                if (encryptedData == null || encryptedData.Length == 0)
                {
                    throw new Exception("Encryption produced no data");
                }

                // Combine all components
                List<byte> sealedData = new List<byte>();
                sealedData.AddRange(salt); // 16 bytes
                sealedData.AddRange(iv);   // 16 bytes
                sealedData.AddRange(metadataLengthBytes); // 4 bytes
                sealedData.AddRange(metadataBytes); // metadata
                sealedData.AddRange(encryptedData); // encrypted file data

                if (sealedData.Count == 0)
                {
                    throw new Exception("Final sealed data is empty");
                }

                return sealedData;
            }
            catch (Exception ex)
            {
                throw new Exception($"Encryption failed: {ex.Message}", ex);
            }
        }

        public static (List<byte> data, FileMetadata metadata) UnsealFile(List<byte> sealedData, string password)
        {
            try
            {
                if (string.IsNullOrEmpty(password))
                    throw new Exception("Password cannot be empty");

                if (sealedData == null || sealedData.Count < SALT_SIZE + 16 + 4) // Must have salt, IV, and metadata length
                    throw new Exception($"Invalid sealed data format: Data is too short (length: {sealedData?.Count ?? 0})");

                // Extract salt and IV
                byte[] salt = sealedData.GetRange(0, SALT_SIZE).ToArray();
                byte[] iv = sealedData.GetRange(SALT_SIZE, 16).ToArray();

                // Extract metadata length and metadata
                int metadataLength = BitConverter.ToInt32(sealedData.GetRange(SALT_SIZE + 16, 4).ToArray(), 0);
                int metadataStart = SALT_SIZE + 16 + 4;

                if (metadataLength <= 0 || metadataStart + metadataLength > sealedData.Count)
                    throw new Exception($"Invalid metadata length: {metadataLength} (total data length: {sealedData.Count})");

                byte[] metadataBytes = sealedData.GetRange(metadataStart, metadataLength).ToArray();
                string metadataJson = Encoding.UTF8.GetString(metadataBytes);
                FileMetadata metadata = JsonSerializer.Deserialize<FileMetadata>(metadataJson);

                // Extract encrypted data
                int encryptedDataStart = metadataStart + metadataLength;
                if (encryptedDataStart > sealedData.Count)
                    throw new Exception($"Invalid data format: No encrypted data found (start position: {encryptedDataStart}, total length: {sealedData.Count})");

                byte[] encryptedData = sealedData.GetRange(encryptedDataStart,
                    sealedData.Count - encryptedDataStart).ToArray();

                if (encryptedData.Length == 0)
                {
                    return (new List<byte>(), metadata);
                }

                // Generate key from password using PBKDF2
                byte[] key = GenerateKeyFromPassword(password, salt);

                // Decrypt the data
                using (Aes aes = Aes.Create())
                {
                    aes.Key = key;
                    aes.IV = iv;
                    aes.Mode = CipherMode.CBC;
                    aes.Padding = PaddingMode.PKCS7;

                    try
                    {
                        using (MemoryStream ms = new MemoryStream())
                        {
                            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                            {
                                cs.Write(encryptedData, 0, encryptedData.Length);
                                cs.FlushFinalBlock();
                            }
                            byte[] decryptedBytes = ms.ToArray();

                            if (decryptedBytes.Length == 0)
                            {
                                Logger.LogError("Decryption failed: Incorrect password or corrupted data.");
                                return (new List<byte>(), metadata);
                            }
                            return (decryptedBytes.ToList(), metadata);
                        }
                    }
                    catch (CryptographicException cex)
                    {
                        // Instead of throwing, return a special result indicating failure
                        Logger.LogError("Decryption failed: Incorrect password or corrupted data.");
                        return (new List<byte>(), metadata); // Return empty data to indicate failure
                    }
                }
            }
            catch (Exception ex)
            {
                if (ex.Message.Contains("Incorrect password or corrupted data"))
                {
                    // Do not throw, just return empty data to indicate failure
                    Logger.LogError("Decryption failed: Incorrect password or corrupted data.");
                    return (new List<byte>(), null);
                }
                Logger.LogError($"Decryption failed due to an unexpected error: {ex.Message}");
                return (new List<byte>(), null);
            }
        }
    }
}
