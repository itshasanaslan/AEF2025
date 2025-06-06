using System;
using System.IO;
using System.Threading.Tasks;

namespace AEF2025
{
    /// <summary>
    /// Provides logging functionality for the application.
    /// This class handles writing log messages to a file and console.
    /// </summary>
    public static class Logger
    {
        private static readonly string LogDirectory = "logs";
        private static readonly string LogFileName = "encryption_log.txt";
        private static readonly object LogLock = new object();

        static Logger()
        {
            // Create logs directory if it doesn't exist
            if (!Directory.Exists(LogDirectory))
            {
                Directory.CreateDirectory(LogDirectory);
            }
        }

        /// <summary>
        /// Logs an error message.
        /// </summary>
        /// <param name="message">The message to log.</param>
        /// <param name="item">The file item associated with the error.</param>
        public static void Log(string message, FileItem item)
        {
            string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Error on {item.FullPath}: {message}";
            
            // Write to console
            Console.WriteLine(logMessage);

            // Write to file
            string logPath = Path.Combine(LogDirectory, LogFileName);
            lock (LogLock)
            {
                try
                {
                    File.AppendAllText(logPath, logMessage + Environment.NewLine);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to write to log file: {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Logs an informational message.
        /// </summary>
        /// <param name="message">The message to log.</param>
        public static void LogInfo(string message)
        {
            Log("INFO", message);
        }

        /// <summary>
        /// Logs a warning message.
        /// </summary>
        /// <param name="message">The message to log.</param>
        public static void LogWarning(string message)
        {
            Log("WARNING", message);
        }

        /// <summary>
        /// Logs an error message.
        /// </summary>
        /// <param name="message">The message to log.</param>
        public static void LogError(string message)
        {
            Log("ERROR", message);
        }

        /// <summary>
        /// Logs an error message with associated file information.
        /// </summary>
        /// <param name="message">The message to log.</param>
        /// <param name="item">The file item associated with the error.</param>
        public static void LogError(string message, FileItem item)
        {
            Log(message, item);
        }

        /// <summary>
        /// Logs a debug message.
        /// </summary>
        /// <param name="message">The message to log.</param>
        public static void LogDebug(string message)
        {
            Log("DEBUG", message);
        }

        /// <summary>
        /// Logs a message with the specified level.
        /// </summary>
        /// <param name="level">The log level.</param>
        /// <param name="message">The message to log.</param>
        private static void Log(string level, string message)
        {
            try
            {
                var logMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} [{level}] {message}";
                Console.WriteLine(logMessage);

                string logPath = Path.Combine(LogDirectory, LogFileName);
                lock (LogLock)
                {
                    try
                    {
                        File.AppendAllText(logPath, logMessage + Environment.NewLine);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Failed to write to log file: {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error writing to log file: {ex.Message}");
            }
        }

        public static async Task LogAsync(string message, FileItem item)
        {
            string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] Error on {item.FullPath}: {message}";
            
            // Write to console
            Console.WriteLine(logMessage);

            // Write to file
            string logPath = Path.Combine(LogDirectory, LogFileName);
            try
            {
                await File.AppendAllTextAsync(logPath, logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to write to log file: {ex.Message}");
            }
        }

        public static async Task LogAsync(string message)
        {
            string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
            
            // Write to console
            Console.WriteLine(logMessage);

            // Write to file
            string logPath = Path.Combine(LogDirectory, LogFileName);
            try
            {
                await File.AppendAllTextAsync(logPath, logMessage + Environment.NewLine);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to write to log file: {ex.Message}");
            }
        }
    }
}
