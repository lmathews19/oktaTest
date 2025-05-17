using System.Security.Cryptography.X509Certificates;

namespace LocalApp
{
    public class SamlOptions
    {
        public string IdpEntityId { get; set; } = string.Empty;
        public string IdpSsoUrl { get; set; } = string.Empty;
        public X509Certificate2? IdpCertificate { get; set; }

        public string SpEntityId { get; set; } = string.Empty;
        public string AssertionConsumerServiceUrl { get; set; } = string.Empty;
        public X509Certificate2? SpSigningCertificate { get; set; }

        public bool WantAssertionsSigned { get; set; } = true;
        public TimeSpan MaxClockSkew { get; set; } = TimeSpan.FromMinutes(5);
    }
}
