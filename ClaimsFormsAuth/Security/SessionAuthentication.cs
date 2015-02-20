using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Security;

namespace Thinktecture.IdentityModel.Web
{
    public static class SessionAuthentication
    {
        public static void SetAuthCookie(string name, bool isPersistent)
        {
            SetAuthCookie(name, new string[] { }, isPersistent);
        }

        public static void SetAuthCookie(string name, IEnumerable<string> roles, bool isPersistent)
        {
            var claims = (from role in roles
                          select new Claim(ClaimTypes.Role, role)).ToList();
            claims.Add(new Claim(ClaimTypes.Name, name));

            SetAuthCookie(claims, isPersistent);
        }

        public static void SetAuthCookie(IEnumerable<Claim> claims, bool isPersistent)
        {
            if (!HttpContext.Current.Request.IsSecureConnection && FormsAuthentication.RequireSSL)
            {
                throw new HttpException(500, "Connection is not secured with SSL");
            }

            var sessionToken = CreateSessionSecurityToken(CreatePrincipal(claims.ToList()), isPersistent);
            FederatedAuthentication.SessionAuthenticationModule.WriteSessionTokenToCookie(sessionToken);
        }

        public static SessionSecurityToken CreateSessionSecurityToken(ClaimsPrincipal principal, bool isPersistent)
        {
            var token = new SessionSecurityToken(principal, FormsAuthentication.Timeout);
            token.IsPersistent = isPersistent;

            bool enabled;
            if (bool.TryParse(ConfigurationManager.AppSettings["CachePrincipalOnServer"], out enabled))
            {
                token.IsReferenceMode = enabled;
            }

            return token;
        }

        public static void SignOut()
        {
            FederatedAuthentication.SessionAuthenticationModule.SignOut();
        }

        private static ClaimsPrincipal CreatePrincipal(IEnumerable<Claim> claims)
        {
            var id = new ClaimsIdentity(claims, "FormsSessionAuthentication");
            var principal = new ClaimsPrincipal(id);

            //if (FederatedAuthentication.ServiceConfiguration.ClaimsAuthenticationManager != null)
            //{
            //    principal = FederatedAuthentication.ServiceConfiguration.ClaimsAuthenticationManager.Authenticate(
            //        HttpContext.Current.Request.RawUrl,
            //        principal);
            //}

            return principal;
        }
    }
}