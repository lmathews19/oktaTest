using Microsoft.AspNetCore.WebUtilities;
using System.IO.Compression;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace LocalApp
{
    public class SamlService
    {
        private readonly SamlOptions _options;
        private readonly ILogger<SamlService> _logger;

        public SamlService(SamlOptions options, ILogger<SamlService> logger)
        {
            _options = options;
            _logger = logger;
        }

        public string BuildAuthnRequest(string? relayState = null)
        {
            return $"{_options.IdpSsoUrl}";

            /*            _logger.LogInformation("Building SAML AuthnRequest");

                        string requestId = "_" + Guid.NewGuid().ToString();
                        string issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

                        // Build the SAML AuthnRequest XML
                        var sb = new StringBuilder();
                        sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
                        sb.Append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
                        sb.Append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
                        sb.Append($"ID=\"{requestId}\" Version=\"2.0\" ");
                        sb.Append($"IssueInstant=\"{issueInstant}\" ");
                        sb.Append("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ");
                        sb.Append($"AssertionConsumerServiceURL=\"{_options.AssertionConsumerServiceUrl}\" ");
                        sb.Append($"Destination=\"{_options.IdpSsoUrl}\">");
                        sb.Append($"<saml:Issuer>{_options.SpEntityId}</saml:Issuer>");
                        sb.Append("<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" AllowCreate=\"true\"/>");
                        sb.Append("</samlp:AuthnRequest>");

                        string request = sb.ToString();

                        // Sign the request if certificate is provided
                        if (_options.SpSigningCertificate != null)
                        {
                            _logger.LogInformation("Signing SAML AuthnRequest");
                            request = SignSamlRequest(request);
                        }

                        // Encode the request for HTTP-Redirect binding
                        string encodedRequest = EncodeRequest(request);

                        // Build the full redirect URL
                        string redirectUrl = $"{_options.IdpSsoUrl}";//?SAMLRequest={encodedRequest}";

                        // Add RelayState if provided
                        if (!string.IsNullOrEmpty(relayState))
                        {
                            redirectUrl += $"&RelayState={Uri.EscapeDataString(relayState)}";
                        }

                        _logger.LogInformation("SAML AuthnRequest built successfully");
                        return redirectUrl;*/
        }

        private string EncodeRequest(string request)
        {
            var bytes = Encoding.UTF8.GetBytes(request);

            // Deflate compress
            using var compressedStream = new MemoryStream();
            using (var deflateStream = new DeflateStream(compressedStream, CompressionMode.Compress, true))
            {
                deflateStream.Write(bytes, 0, bytes.Length);
            }

            // Convert to Base64
            var base64String = Convert.ToBase64String(compressedStream.ToArray());

            // URL encode
            return WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(base64String));
        }

        private string SignSamlRequest(string samlRequest)
        {
            if (_options.SpSigningCertificate == null)
            {
                throw new InvalidOperationException("Signing certificate is not provided");
            }

            var xmlDoc = new XmlDocument { PreserveWhitespace = true };
            xmlDoc.LoadXml(samlRequest);

            // Create a SignedXml object with the SAML XML document
            var signedXml = new SignedXml(xmlDoc);

            // Add the key to the SignedXml document
            signedXml.SigningKey = _options.SpSigningCertificate.GetRSAPrivateKey();

            // Create a reference to be signed
            var reference = new Reference { Uri = "" };

            // Add an enveloped transformation to the reference
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigC14NTransform());

            // Add the reference to the SignedXml object
            signedXml.AddReference(reference);

            // Add KeyInfo
            var keyInfo = new KeyInfo();
            keyInfo.AddClause(new KeyInfoX509Data(_options.SpSigningCertificate));
            signedXml.KeyInfo = keyInfo;

            // Compute the signature
            signedXml.ComputeSignature();

            // Get the XML representation of the signature
            var xmlSignature = signedXml.GetXml();

            // Append the signature to the SAML request
            var rootElement = xmlDoc.DocumentElement;
            rootElement?.AppendChild(xmlDoc.ImportNode(xmlSignature, true));

            return xmlDoc.OuterXml;
        }

        public ClaimsPrincipal ProcessSamlResponse(string base64Response)
        {
            _logger.LogInformation("Processing SAML Response");

            try
            {
                // Decode the SAML response from Base64
                var samlBytes = Convert.FromBase64String(base64Response);
                var samlResponse = Encoding.UTF8.GetString(samlBytes);

                // Load the XML document
                var xmlDoc = new XmlDocument { PreserveWhitespace = true };
                xmlDoc.LoadXml(samlResponse);

                // Set up XML namespaces for XPath queries
                var nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
                nsManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
                nsManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
                nsManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

                // Verify response status
                var statusNode = xmlDoc.SelectSingleNode("//samlp:StatusCode", nsManager);
                var statusValue = statusNode?.Attributes?["Value"]?.Value;
                if (statusValue != "urn:oasis:names:tc:SAML:2.0:status:Success")
                {
                    _logger.LogError("SAML Response status is not Success: {Status}", statusValue);
                    throw new Exception($"SAML Response status is not Success: {statusValue}");
                }

                // Verify the issuer
                var issuerNode = xmlDoc.SelectSingleNode("//saml:Issuer", nsManager);
                if (issuerNode == null || issuerNode.InnerText != _options.IdpEntityId)
                {
                    _logger.LogError("Invalid issuer in SAML response");
                    throw new Exception("Invalid issuer in SAML response");
                }

                // Verify signature if required
                if (_options.WantAssertionsSigned && _options.IdpCertificate != null)
                {
                    ValidateSignature(xmlDoc);
                }

                // Extract assertions and claims
                return ExtractClaims(xmlDoc, nsManager);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SAML response");
                throw;
            }
        }

        private void ValidateSignature(XmlDocument xmlDoc)
        {
            _logger.LogInformation("Validating SAML Response signature");

            if (_options.IdpCertificate == null)
            {
                throw new InvalidOperationException("IdP certificate is not provided for signature validation");
            }

            // Extract the RSA public key using the recommended method
            using var rsaPublicKey = _options.IdpCertificate.GetRSAPublicKey();
            if (rsaPublicKey == null)
            {
                throw new InvalidOperationException("Failed to extract RSA public key from IdP certificate");
            }

            // Set up namespaces for XPath
            var nsManager = new XmlNamespaceManager(xmlDoc.NameTable);
            nsManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");
            nsManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            nsManager.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

            // Look for signature in the response or assertion
            var signatureNode = xmlDoc.SelectSingleNode("//ds:Signature", nsManager);
            if (signatureNode == null)
            {
                _logger.LogError("No signature found in SAML response");
                throw new Exception("No signature found in SAML response");
            }

            // Create a SignedXml object for verification
            var signedXml = new SignedXml(xmlDoc);
            signedXml.LoadXml(signatureNode as XmlElement);


            // Verify the signature using the extracted RSA public key
            if (!signedXml.CheckSignature(rsaPublicKey))
            {
                _logger.LogError("SAML Response signature validation failed");
                throw new Exception("SAML Response signature validation failed");
            }

            _logger.LogInformation("SAML Response signature validated successfully");
        }

        private ClaimsPrincipal ExtractClaims(XmlDocument xmlDoc, XmlNamespaceManager nsManager)
        {
            _logger.LogInformation("Extracting claims from SAML Response");

            var claims = new List<Claim>();

            // Extract NameID
            var nameIdNode = xmlDoc.SelectSingleNode("//saml:NameID", nsManager);
            if (nameIdNode != null)
            {
                string nameId = nameIdNode.InnerText;
                claims.Add(new Claim(ClaimTypes.NameIdentifier, nameId));
                claims.Add(new Claim(ClaimTypes.Name, nameId));

                _logger.LogInformation("Found NameID: {NameId}", nameId);
            }

            // Extract attributes
            var attributeNodes = xmlDoc.SelectNodes("//saml:AttributeStatement/saml:Attribute", nsManager);
            if (attributeNodes != null)
            {
                foreach (XmlNode attribute in attributeNodes)
                {
                    string? attributeName = attribute.Attributes?["Name"]?.Value;
                    if (string.IsNullOrEmpty(attributeName))
                        continue;

                    var attributeValues = attribute.SelectNodes("saml:AttributeValue", nsManager);
                    if (attributeValues != null)
                    {
                        foreach (XmlNode valueNode in attributeValues)
                        {
                            string attributeValue = valueNode.InnerText;
                            string claimType = MapToClaimType(attributeName);
                            claims.Add(new Claim(claimType, attributeValue));

                            _logger.LogInformation("Found claim: {ClaimType} = {ClaimValue}", claimType, attributeValue);
                        }
                    }
                }
            }

            // Create identity and principal
            var identity = new ClaimsIdentity(claims, "SAML2");
            return new ClaimsPrincipal(identity);
        }

        private string MapToClaimType(string attributeName)
        {
            // Map SAML attribute names to ClaimTypes
            return attributeName switch
            {
                "email" or "emailAddress" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" => ClaimTypes.Email,
                "givenName" or "firstName" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" => ClaimTypes.GivenName,
                "surname" or "lastName" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" => ClaimTypes.Surname,
                "name" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" => ClaimTypes.Name,
                "role" or "http://schemas.microsoft.com/ws/2008/06/identity/claims/role" => ClaimTypes.Role,
                _ => attributeName // Use original name if no mapping exists
            };
        }
    }
}
