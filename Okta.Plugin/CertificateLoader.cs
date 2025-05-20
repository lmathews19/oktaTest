using Microsoft.Extensions.Logging;
using System.Security.Cryptography.X509Certificates;

namespace Okta.Plugin
{
    public class CertificateLoader
    {
        private readonly ILogger<CertificateLoader> _logger;

        public CertificateLoader(ILogger<CertificateLoader> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// Load certificate from a .cer, .crt, or .pem file
        /// </summary>
        public X509Certificate2 LoadCertificate(string filePath)
        {
            try
            {
                _logger.LogInformation("Loading certificate from: {FilePath}", filePath);

                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"Certificate file not found: {filePath}");
                }

                return new X509Certificate2(filePath);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading certificate from file: {FilePath}", filePath);
                throw;
            }
        }

        /// <summary>
        /// Load certificate from a .pfx file with password
        /// </summary>
        public X509Certificate2 LoadPfxCertificate(string filePath, string password)
        {
            try
            {
                _logger.LogInformation("Loading PFX certificate from: {FilePath}", filePath);

                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"PFX certificate file not found: {filePath}");
                }

                return new X509Certificate2(filePath, password,
                    X509KeyStorageFlags.MachineKeySet |
                    X509KeyStorageFlags.PersistKeySet |
                    X509KeyStorageFlags.Exportable);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading PFX certificate from file: {FilePath}", filePath);
                throw;
            }
        }

        /// <summary>
        /// Load certificate from base64 string
        /// </summary>
        public X509Certificate2 LoadFromBase64String(string base64String)
        {
            try
            {
                _logger.LogInformation("Loading certificate from base64 string");

                byte[] certificateData = Convert.FromBase64String(base64String);
                return new X509Certificate2(certificateData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error loading certificate from base64 string");
                throw;
            }
        }
    }
}
