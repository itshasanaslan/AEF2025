using System;
using System.IO;

namespace AEF2025
{
    /// <summary>
    /// Represents metadata for a file, including its original name, extension, and timestamps.
    /// </summary>
    public class FileMetadata
    {
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
        /// Gets or sets the last access time of the file.
        /// </summary>
        public DateTime LastAccessTime { get; set; }

        /// <summary>
        /// Gets or sets the last write time of the file.
        /// </summary>
        public DateTime LastWriteTime { get; set; }

        /// <summary>
        /// Gets or sets the file attributes.
        /// </summary>
        public FileAttributes Attributes { get; set; }
    }
} 