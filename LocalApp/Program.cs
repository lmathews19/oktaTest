using LocalApp;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

// Add CertificateLoader service
builder.Services.AddSingleton<IAMOnline.Plugin.CertificateLoader>();

// Configure SAML Options
builder.Services.AddSingleton(serviceProvider =>
{
    var logger = serviceProvider.GetRequiredService<ILogger<IAMOnline.Plugin.CertificateLoader>>();
    var certificateLoader = new IAMOnline.Plugin.CertificateLoader(logger);

    // Get paths from configuration
    var idpCertPath = Path.Combine(builder.Environment.ContentRootPath, "Certificates", "idp-certificate.crt");
    var spCertPath = Path.Combine(builder.Environment.ContentRootPath, "Certificates", "sp-certificate.pfx");
    var spCertPassword = builder.Configuration["SamlOptions:SpCertificatePassword"] ?? "YourCertPassword";

    // Load certificates
    X509Certificate2? idpCertificate = null;
    X509Certificate2? spCertificate = null;

    try
    {
        idpCertificate = certificateLoader.LoadCertificate(idpCertPath);
    }
    catch (System.Exception ex)
    {
        logger.LogError(ex, "Failed to load IdP certificate. SAML validation will be limited.");
    }

    try
    {
        spCertificate = certificateLoader.LoadPfxCertificate(spCertPath, spCertPassword);
    }
    catch (System.Exception ex)
    {
        logger.LogError(ex, "Failed to load SP certificate. SAML requests will not be signed.");
    }

    // Create and configure SAML options
    return new IAMOnline.Plugin.SamlOptions
    {
        IdpEntityId = builder.Configuration["SamlOptions:IdpEntityId"] ?? "http://www.okta.com/exampleEntityId",
        IdpSsoUrl = builder.Configuration["SamlOptions:IdpSsoUrl"] ?? "https://your-okta-domain.okta.com/app/exampleapp/exampleappid/sso/saml",
        IdpCertificate = idpCertificate,

        SpEntityId = builder.Configuration["SamlOptions:SpEntityId"] ?? "https://localhost:7286/",
        AssertionConsumerServiceUrl = builder.Configuration["SamlOptions:AssertionConsumerServiceUrl"] ?? "https://localhost:7286/Auth/AssertionConsumerService",
        SpSigningCertificate = spCertificate,

        WantAssertionsSigned = bool.Parse(builder.Configuration["SamlOptions:WantAssertionsSigned"] ?? "true")
    };
});
// Add SAML Service
builder.Services.AddSingleton<IAMOnline.Plugin.SamlService>();

// Add Cookie Authentication
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.LoginPath = "/Auth/Login";
    options.LogoutPath = "/Auth/Logout";
    options.AccessDeniedPath = "/Home/AccessDenied";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
});

// Add authorization for role-based or policy-based security
builder.Services.AddAuthorization(options =>
{
    // You can define policies based on claims from SAML response
    options.AddPolicy("RequireAdminRole", policy => policy.RequireRole("Admin"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
