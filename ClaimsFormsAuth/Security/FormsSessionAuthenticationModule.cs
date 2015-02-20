using System;
using System.Configuration;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Web;
using System.Web.Security;

namespace Thinktecture.IdentityModel.Web
{
    public class FormsSessionAuthenticationModule : SessionAuthenticationModule
    {
        protected bool IsSlidingExpiration { get; set; }
        protected TimeSpan Timeout { get; set; }
        protected string LoginUrl { get; set; }
        protected string CookieName { get; set; }
        protected string CookieDomain { get; set; }
        protected bool RequireSsl { get; set; }
        protected bool CachePrincipalOnServer { get; set; }

        protected override void InitializeModule(HttpApplication context)
        {
            base.InitializeModule(context);

            context.EndRequest += OnEndRequest;
        }

        protected override void InitializePropertiesFromConfiguration()
        {
            base.InitializePropertiesFromConfiguration();

            // read formsauth configuration
            IsSlidingExpiration = FormsAuthentication.SlidingExpiration;
            Timeout = FormsAuthentication.Timeout;
            LoginUrl = FormsAuthentication.LoginUrl;
            CookieName = FormsAuthentication.FormsCookieName;
            CookieDomain = FormsAuthentication.CookieDomain;
            RequireSsl = FormsAuthentication.RequireSSL;
            
            // read other configuration
            CachePrincipalOnServer = false;
            bool enabled;
            if (bool.TryParse(ConfigurationManager.AppSettings["CachePrincipalOnServer"], out enabled))
            {
                CachePrincipalOnServer = enabled;
            }

            // configure cookie handler
            CookieHandler.Name = CookieName;
            CookieHandler.Domain = CookieDomain;
            CookieHandler.RequireSsl = RequireSsl;
        }

        protected override void OnSessionSecurityTokenReceived(SessionSecurityTokenReceivedEventArgs e)
        {
            base.OnSessionSecurityTokenReceived(e);

            if (IsSlidingExpiration)
            {
                if (NeedsRenew(e.SessionToken))
                {
                    e.SessionToken = CreateSessionSecurityToken(
                         e.SessionToken.ClaimsPrincipal,
                         e.SessionToken.Context,
                         DateTime.UtcNow,
                         DateTime.UtcNow.Add(Timeout),
                         e.SessionToken.IsPersistent);

                    e.SessionToken.IsReferenceMode = CachePrincipalOnServer;
                    e.ReissueCookie = true;
                }
            }
        }

        void OnEndRequest(object sender, EventArgs e)
        {
            var context = (sender as HttpApplication).Context;

            if (context.Response.StatusCode == 401)
            {
                var noRedirect = context.Items["NoRedirect"];

                if (noRedirect == null)
                {
                    var loginUrl = LoginUrl + "?returnUrl=" + HttpUtility.UrlEncode(context.Request.RawUrl, context.Request.ContentEncoding);
                    context.Response.Redirect(loginUrl);
                }
            }
        }

        protected virtual bool NeedsRenew(SessionSecurityToken token)
        {
            DateTime utcNow = DateTime.UtcNow;

            TimeSpan span = (TimeSpan)(utcNow - token.ValidFrom);
            TimeSpan span2 = (TimeSpan)(token.ValidTo - utcNow);
            
            if (span2 > span)
            {
                return false;
            }

            return true;
        }
    }
}