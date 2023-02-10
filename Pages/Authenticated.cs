using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using SampleApplication;

[Authorize]
public class AuthenticatedModel : PageModel
{
    public string Username { get; set; }
    public string AccessToken { get; set; }
    public string RefreshToken { get; set; }
    public string IdToken { get; set; }

    private readonly TokenClient tokenClient;

    public AuthenticatedModel(TokenClient tokenClient)
    {
        this.tokenClient = tokenClient;
    }

    public async Task OnGet()
    {
        ClaimsPrincipal user = this.User;
        var username = user.FindFirstValue("username");
        this.Username = $"{username}";

        this.AccessToken = await this.tokenClient.GetAccessToken(this.HttpContext);
        this.RefreshToken = await this.tokenClient.GetRefreshToken(this.HttpContext);
        this.IdToken = await this.tokenClient.GetIdToken(this.HttpContext);
    }

    public async Task<IActionResult> OnPostRefreshToken()
    {
        await this.tokenClient.RefreshAccessToken(this.HttpContext);
        this.AccessToken = await this.tokenClient.GetAccessToken(this.HttpContext);
        this.IdToken = await this.tokenClient.GetIdToken(this.HttpContext);
        this.RefreshToken = await this.tokenClient.GetRefreshToken(this.HttpContext);
        return Page();
    }

    public async Task OnPostLogout()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme);
    }
}
