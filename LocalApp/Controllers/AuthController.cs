using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;

namespace LocalApp.Controllers
{
    public class AuthController : Controller
    {
        private readonly Okta.Plugin.SamlService _samlService;
        private readonly ILogger<AuthController> _logger;

        public AuthController(Okta.Plugin.SamlService samlService, ILogger<AuthController> logger)
        {
            _samlService = samlService;
            _logger = logger;
        }

        public IActionResult Login(string returnUrl = "/")
        {
            _logger.LogInformation("Initiating SAML login request");

            try
            {
                // Store the return URL in TempData
                TempData["ReturnUrl"] = returnUrl;

                // Build the SAML request and get the redirect URL
                string redirectUrl = _samlService.BuildAuthnRequest(returnUrl);

                _logger.LogInformation("Redirecting to IdP for authentication");
                return Redirect(redirectUrl);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error initiating SAML login");
                return RedirectToAction("Error", "Home", new { message = "Authentication request failed" });
            }
        }

        [HttpPost]
        public async Task<IActionResult> Acs()
        {
            _logger.LogInformation("Received SAML response");

            try
            {
                // Get the SAML response from the form
                if (!Request.Form.ContainsKey("SAMLResponse"))
                {
                    _logger.LogError("No SAMLResponse found in the request");
                    return BadRequest("No SAML response received");
                }

                string samlResponse = Request.Form["SAMLResponse"];

                // Process the SAML response and get claims
                var principal = _samlService.ProcessSamlResponse(samlResponse);

                // Set authentication cookie
                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    principal,
                    new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTime.UtcNow.AddHours(8)
                    });

                // Redirect to the return URL or default page
                string returnUrl = string.Empty;
                if (Request.Form.ContainsKey("RelayState"))
                {
                    returnUrl = Request.Form["RelayState"];
                }
                else if (TempData.ContainsKey("ReturnUrl"))
                {
                    returnUrl = TempData["ReturnUrl"] as string ?? "/";
                }

                _logger.LogInformation("Successfully authenticated user, redirecting to: {ReturnUrl}",
                    !string.IsNullOrEmpty(returnUrl) ? returnUrl : "/");

                return Redirect(!string.IsNullOrEmpty(returnUrl) ? returnUrl : "/");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing SAML response");
                return RedirectToAction("Error", "Home", new { message = "Authentication failed" });
            }
        }

        public async Task<IActionResult> Logout()
        {
            _logger.LogInformation("Logging out user");

            // Sign out locally
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            // Clear authentication (if using cookies authentication)
            //HttpContext.SignOutAsync();

            // Remove all cookies
            foreach (var cookie in Request.Cookies.Keys)
            {
                Response.Cookies.Delete(cookie);
            }

            // Redirect to home or login page
            return RedirectToAction("Index", "Home");
        }
    }
}
