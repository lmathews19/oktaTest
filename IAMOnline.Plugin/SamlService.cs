using Microsoft.Extensions.Logging;
using System.IO.Compression;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace IAMOnline.Plugin
{
    public class SamlService
    {
        private readonly SamlOptions _options;
        private readonly ILogger<SamlService> _logger;
        private static readonly HashSet<string> ProcessedAssertionIds = new HashSet<string>();

        public SamlService(SamlOptions options, ILogger<SamlService> logger)
        {
            _options = options;
            _logger = logger;
        }

        public string BuildAuthnRequest(string? relayState = null)
        {
            // return $"{_options.IdpSsoUrl}";

            _logger.LogInformation("Building SAML AuthnRequest");

            string requestId = "_" + Guid.NewGuid().ToString();
            string issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

            // Build the SAML AuthnRequest XML
            var sb = new StringBuilder();
            //sb.Append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
            sb.Append("<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ");
            sb.Append("xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ");
            sb.Append($"ID=\"{requestId}\" Version=\"2.0\" ");
            sb.Append($"IssueInstant=\"{issueInstant}\" ");
            sb.Append("ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" ");
            sb.Append($"AssertionConsumerServiceURL=\"{_options.AssertionConsumerServiceUrl}\" ");
            sb.Append($"Destination=\"{_options.IdpSsoUrl}\">");
            sb.Append($"<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">{_options.IdpEntityId}</saml:Issuer>");
            sb.Append("<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" AllowCreate=\"true\"/>");
            sb.Append("</samlp:AuthnRequest>");

            string request = sb.ToString();

            MemoryStream memoryStream = new MemoryStream();
            StreamWriter writer = new StreamWriter(new DeflateStream(memoryStream, CompressionMode.Compress, true), new UTF8Encoding(false));
            writer.Write(request);
            writer.Close();
            string result = Convert.ToBase64String(memoryStream.GetBuffer(), 0, (int)memoryStream.Length, Base64FormattingOptions.None);

            // Build the full redirect URL
            string redirectUrl = $"{_options.IdpSsoUrl}?SAMLRequest={Uri.EscapeDataString(result)}";

            // Add RelayState if provided
            if (!string.IsNullOrEmpty(relayState))
            {
                redirectUrl += $"&RelayState={Uri.EscapeDataString(relayState)}";
            }

            _logger.LogInformation($"SAML AuthnRequest built successfully");
            return redirectUrl;
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
                nsManager.AddNamespace("saml2", "urn:oasis:names:tc:SAML:2.0:assertion");



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

                // Validate assertion
                ValidateAssertion(xmlDoc, nsManager);

                // Extract assertions and claims
                return ExtractClaims(xmlDoc, nsManager);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SAML response");
                throw;
            }
        }

        private void ValidateSignature(XmlDocument xmlDoc, XmlNamespaceManager nsManager)
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

        private void ValidateAssertion(XmlDocument xmlDoc, XmlNamespaceManager nsManager)
        {
            // Verify signature if certificate is available
            if (_options.IdpCertificate != null)
            {
                ValidateSignature(xmlDoc, nsManager);
            }

            // 1. Get Assertion node
            var assertionNode = xmlDoc.SelectSingleNode("//saml2:Assertion", nsManager);
            if (assertionNode == null)
                throw new Exception("No Assertion found in SAML response.");

            // 1. Replay Attack Protection
            var assertionId = assertionNode.Attributes?["ID"]?.Value;
            if (string.IsNullOrEmpty(assertionId))
                throw new Exception("Assertion ID missing.");
            lock (ProcessedAssertionIds)
            {
                if (!ProcessedAssertionIds.Add(assertionId))
                    throw new Exception("Replay attack detected: Assertion ID already processed.");
            }

            // 2. Assertion Expiry and NotBefore/NotOnOrAfter
            var conditionsNode = assertionNode.SelectSingleNode("saml2:Conditions", nsManager);
            if (conditionsNode == null)
                throw new Exception("No Conditions element in Assertion.");

            var notBeforeStr = conditionsNode.Attributes?["NotBefore"]?.Value;
            var notOnOrAfterStr = conditionsNode.Attributes?["NotOnOrAfter"]?.Value;
            var now = DateTime.UtcNow;
            var skew = _options.MaxClockSkew;

            if (!string.IsNullOrEmpty(notBeforeStr) &&
                DateTime.TryParse(notBeforeStr, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var notBefore))
            {
                if (now + skew < notBefore)
                    throw new Exception("Assertion is not yet valid (NotBefore).");
            }
            if (!string.IsNullOrEmpty(notOnOrAfterStr) &&
                DateTime.TryParse(notOnOrAfterStr, null, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal, out var notOnOrAfter))
            {
                if (now - skew >= notOnOrAfter)
                    throw new Exception("Assertion has expired (NotOnOrAfter).");
            }

            // 3. Audience Restriction
            var audienceNode = conditionsNode.SelectSingleNode("saml2:AudienceRestriction/saml2:Audience", nsManager);
            if (audienceNode == null || audienceNode.InnerText != _options.SpEntityId)
                throw new Exception("Audience restriction failed.");

            // 4. Recipient/ACS URL Validation
            var recipientNode = assertionNode.SelectSingleNode("saml2:Subject/saml2:SubjectConfirmation/saml2:SubjectConfirmationData", nsManager);
            var recipient = recipientNode?.Attributes?["Recipient"]?.Value;
            if (recipient != _options.AssertionConsumerServiceUrl)
                throw new Exception("Recipient does not match ACS URL.");

            // 5. Session Fixation: Regenerate session in your controller after authentication
        }

        private ClaimsPrincipal ExtractClaims(XmlDocument xmlDoc, XmlNamespaceManager nsManager)
        {
            _logger.LogInformation("Extracting claims from SAML Response");

            // Extract and log AuthnStatement attributes (AuthnInstant, SessionIndex, SessionNotOnOrAfter)
            var authnStatementNode = xmlDoc.SelectSingleNode("//saml2:AuthnStatement", nsManager);
            if (authnStatementNode != null && authnStatementNode.Attributes != null)
            {
/*                var authnInstant = authnStatementNode.Attributes["AuthnInstant"]?.Value;
                var sessionIndex = authnStatementNode.Attributes["SessionIndex"]?.Value;
                var sessionNotOnOrAfter = authnStatementNode.Attributes["SessionNotOnOrAfter"]?.Value;

                _logger.LogInformation("AuthnStatement AuthnInstant: {AuthnInstant}", authnInstant);
                _logger.LogInformation("AuthnStatement SessionIndex: {SessionIndex}", sessionIndex);
                _logger.LogInformation("AuthnStatement SessionNotOnOrAfter: {SessionNotOnOrAfter}", sessionNotOnOrAfter);
*/
                // Optionally, log all attributes
                foreach (XmlAttribute attr in authnStatementNode.Attributes)
                {
                    _logger.LogInformation("AuthnStatement Attribute: {AttributeName} = <value>", attr.Name);
                }
            }
            else
            {
                _logger.LogWarning("No AuthnStatement found in SAML Assertion.");
            }

            var claims = new List<Claim>();

            // Extract NameID
            var nameIdNode = xmlDoc.SelectSingleNode("//saml:NameID", nsManager);
            if (nameIdNode != null)
            {
                string nameId = nameIdNode.InnerText;
                claims.Add(new Claim(ClaimTypes.NameIdentifier, nameId));

                _logger.LogInformation("Found NameID: <userid>");
            }


            // Create identity and principal
            var identity = new ClaimsIdentity(claims, "SAML2");
            return new ClaimsPrincipal(identity);
        }

    }
}
