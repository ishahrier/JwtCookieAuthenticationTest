using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace TokenAuthentication.Controllers
{
    public class AccountController : Controller
    {

        class i
        {
            public string userName;
            public string password;
        }
        public class Token
        {
            public AccessToken accessToken;
            public string refreshToken;
        }
        public sealed class AccessToken
        {
            public string token;
            public int expiresIn;
            
        }
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(string username, string password, string ReturnUrl = "")
        {

            var successful = false;
            var client = new HttpClient();
            client.BaseAddress = new Uri("http://localhost:5000");
            i obj = new i { userName = username, password = password };
            var result = await client.PostAsJsonAsync<i>("/api/auth/login", obj);
            var token = await result.Content.ReadAsAsync<Token>();

            JwtSecurityTokenHandler hand = new JwtSecurityTokenHandler();
            //read the token as recommended by Coxkie and dpix
            var tokenS = hand.ReadJwtToken(token.accessToken.token);
            if (successful)
            {
                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, username),
                    new Claim("FullName", username),
                    new Claim(ClaimTypes.Role, "SuperAdmin"),
                };

                var claimsIdentity = new ClaimsIdentity(
                    claims, CookieAuthenticationDefaults.AuthenticationScheme);

                var authProperties = new AuthenticationProperties
                {
                    //AllowRefresh = <bool>,
                    // Refreshing the authentication session should be allowed.

                    //ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10),
                    // The time at which the authentication ticket expires. A 
                    // value set here overrides the ExpireTimeSpan option of 
                    // CookieAuthenticationOptions set with AddCookie.

                    //IsPersistent = true,
                    // Whether the authentication session is persisted across 
                    // multiple requests. Required when setting the 
                    // ExpireTimeSpan option of CookieAuthenticationOptions 
                    // set with AddCookie. Also required when setting 
                    // ExpiresUtc.

                    //IssuedUtc = <DateTimeOffset>,
                    // The time at which the authentication ticket was issued.

                    //RedirectUri = <string>
                    // The full path or absolute URI to be used as an http 
                    // redirect response value.
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);
                return Redirect(ReturnUrl);
            }
            else
            {
                return new ContentResult()
                {
                    Content = "Invalid username/password",
                };
            }

        }
    }
}