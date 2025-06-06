using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.IO;
using System.Text.Json;

namespace AEF2025
{
    /// <summary>
    /// Manages password operations including validation, hashing, and verification.
    /// This class provides secure password handling functionality.
    /// </summary>
    public class PasswordManager
    {
        /// <summary>
        /// The size of the salt used in password hashing (in bytes).
        /// </summary>
        private const int SALT_SIZE = 16;

        /// <summary>
        /// The number of iterations used in password hashing.
        /// </summary>
        private const int ITERATIONS = 100000;

        /// <summary>
        /// The size of the hash output (in bytes).
        /// </summary>
        private const int HASH_SIZE = 32;

        /// <summary>
        /// The minimum length required for a password.
        /// </summary>
        private const int MIN_PASSWORD_LENGTH = 8;

        /// <summary>
        /// The maximum length allowed for a password.
        /// </summary>
        private const int MAX_PASSWORD_LENGTH = 128;

        /// <summary>
        /// The path to the password hash file.
        /// </summary>
        private readonly string _passwordHashPath;

        /// <summary>
        /// Initializes a new instance of the PasswordManager class.
        /// </summary>
        /// <param name="passwordHashPath">The path to the password hash file.</param>
        public PasswordManager(string passwordHashPath)
        {
            _passwordHashPath = passwordHashPath;
        }

        /// <summary>
        /// Validates a password against the stored hash.
        /// </summary>
        /// <param name="password">The password to validate.</param>
        /// <returns>True if the password is valid, false otherwise.</returns>
        /// <exception cref="Exception">Thrown when there is an error during validation.</exception>
        public bool ValidatePassword(string password)
        {
            try
            {
                if (!File.Exists(_passwordHashPath))
                {
                    return false;
                }

                var storedHash = File.ReadAllBytes(_passwordHashPath);
                if (storedHash.Length != SALT_SIZE + HASH_SIZE)
                {
                    return false;
                }

                var salt = storedHash.Take(SALT_SIZE).ToArray();
                var hash = storedHash.Skip(SALT_SIZE).ToArray();

                var computedHash = ComputeHash(password, salt);
                return hash.SequenceEqual(computedHash);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error validating password: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Sets a new password.
        /// </summary>
        /// <param name="password">The new password to set.</param>
        /// <exception cref="ArgumentException">Thrown when the password is invalid.</exception>
        /// <exception cref="Exception">Thrown when there is an error setting the password.</exception>
        public void SetPassword(string password)
        {
            try
            {
                if (!IsPasswordValid(password))
                {
                    throw new ArgumentException("Invalid password format");
                }

                var salt = new byte[SALT_SIZE];
                using (var rng = new RNGCryptoServiceProvider())
                {
                    rng.GetBytes(salt);
                }

                var hash = ComputeHash(password, salt);
                var storedHash = new byte[SALT_SIZE + HASH_SIZE];
                Buffer.BlockCopy(salt, 0, storedHash, 0, SALT_SIZE);
                Buffer.BlockCopy(hash, 0, storedHash, SALT_SIZE, HASH_SIZE);

                File.WriteAllBytes(_passwordHashPath, storedHash);
            }
            catch (Exception ex)
            {
                throw new Exception($"Error setting password: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Checks if a password meets the required format.
        /// </summary>
        /// <param name="password">The password to check.</param>
        /// <returns>True if the password is valid, false otherwise.</returns>
        public bool IsPasswordValid(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                return false;
            }

            if (password.Length < MIN_PASSWORD_LENGTH || password.Length > MAX_PASSWORD_LENGTH)
            {
                return false;
            }

            // Check for at least one uppercase letter
            if (!password.Any(char.IsUpper))
            {
                return false;
            }

            // Check for at least one lowercase letter
            if (!password.Any(char.IsLower))
            {
                return false;
            }

            // Check for at least one digit
            if (!password.Any(char.IsDigit))
            {
                return false;
            }

            // Check for at least one special character
            if (!password.Any(c => !char.IsLetterOrDigit(c)))
            {
                return false;
            }

            return true;
        }

        /// <summary>
        /// Computes a hash for a password using the specified salt.
        /// </summary>
        /// <param name="password">The password to hash.</param>
        /// <param name="salt">The salt to use in hashing.</param>
        /// <returns>The computed hash as a byte array.</returns>
        private byte[] ComputeHash(string password, byte[] salt)
        {
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, ITERATIONS, HashAlgorithmName.SHA256))
            {
                return pbkdf2.GetBytes(HASH_SIZE);
            }
        }

        private const string PASSWORD_FILE = "password_hint.dat";
        private const int HINT_LENGTH = 4; // Show first 4 characters of password
        private static readonly byte[] KEY = new byte[] { 0x13, 0x37, 0x42, 0x69, 0x24, 0x7B, 0x3C, 0x8D, 0x5E, 0x9F, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F };
        private static readonly byte[] IV = new byte[] { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x7A, 0x8B, 0x9C, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B, 0x5C, 0x6D };

        public class PasswordHint
        {
            public string Hint { get; set; }
            public string EncryptedPassword { get; set; }
            public DateTime CreatedAt { get; set; }
        }

        public static void SavePassword(string password)
        {
            try
            {
                var hint = new PasswordHint
                {
                    Hint = password.Substring(0, Math.Min(HINT_LENGTH, password.Length)) + "..." + password.Length,
                    EncryptedPassword = EncryptPassword(password),
                    CreatedAt = DateTime.Now
                };

                string json = JsonSerializer.Serialize(hint);
                File.WriteAllText(PASSWORD_FILE, json);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to save password hint: {ex.Message}", ex);
            }
        }

        public static string GetPasswordHint()
        {
            try
            {
                if (!File.Exists(PASSWORD_FILE))
                    return "No password hint found.";

                string json = File.ReadAllText(PASSWORD_FILE);
                var hint = JsonSerializer.Deserialize<PasswordHint>(json);
                return $"Password hint: {hint.Hint} (Created: {hint.CreatedAt:yyyy-MM-dd HH:mm:ss})";
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to read password hint: {ex.Message}", ex);
            }
        }

        public static string RecoverPassword()
        {
            try
            {
                if (!File.Exists(PASSWORD_FILE))
                    throw new Exception("No password recovery data found.");

                string json = File.ReadAllText(PASSWORD_FILE);
                var hint = JsonSerializer.Deserialize<PasswordHint>(json);
                return DecryptPassword(hint.EncryptedPassword);
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to recover password: {ex.Message}", ex);
            }
        }

        private static string EncryptPassword(string password)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = KEY;
                aes.IV = IV;

                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(password);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        private static string DecryptPassword(string encryptedPassword)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = KEY;
                aes.IV = IV;

                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(encryptedPassword)))
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }
    }
} 