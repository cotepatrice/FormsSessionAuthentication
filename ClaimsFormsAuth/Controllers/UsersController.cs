using System.Collections.Generic;
using System.IdentityModel.Services;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Web.Mvc;
using System.Web.Security;
using System.Xml;
using System.Xml.Linq;
using Thinktecture.IdentityServer.Samples.RelyingParty.Web.Models;
using SessionSecurityTokenHandler = System.IdentityModel.Tokens.SessionSecurityTokenHandler;

namespace ClaimsFormsAuth.Controllers
{
    [Authorize]
    public class UsersController : Controller
    {
        public ActionResult Index()
        {
            return View("Claims", HttpContext.User);
        }

        public ActionResult SessionToken()
        {
            var model = new SessionTokenModel();
            var cookieHandler = FederatedAuthentication.SessionAuthenticationModule.CookieHandler;

            var cookieBytes = cookieHandler.Read();
            if (cookieBytes != null && cookieBytes.Length != 0)
            {
                model.Size = cookieBytes.Length;

                var sam = FederatedAuthentication.SessionAuthenticationModule;
                var sessionToken = sam.ReadSessionTokenFromCookie(cookieBytes);

                model.IsPersistent = sessionToken.IsPersistent;
                model.IsReferenceMode = sessionToken.IsReferenceMode;
                model.ValidFrom = sessionToken.ValidFrom;
                model.ValidTo = sessionToken.ValidTo;
                model.Context = sessionToken.Context;
                model.ContextId = sessionToken.ContextId.ToString();
                model.EndpointId = sessionToken.EndpointId;

                var cookie = Request.Cookies[FormsAuthentication.FormsCookieName];
                model.CookieExpires = cookie.Expires;

                return View(model);
            }

            return null;
        }

        public ActionResult SessionTokenRaw()
        {
            var cookieHandler = FederatedAuthentication.SessionAuthenticationModule.CookieHandler;
            var cookieBytes = cookieHandler.Read();
            if (cookieBytes != null && cookieBytes.Length != 0)
            {
                var handler = new SessionSecurityTokenHandler();
                var sam = FederatedAuthentication.SessionAuthenticationModule;
                var sessionToken = sam.ReadSessionTokenFromCookie(cookieBytes);
                var sb = new StringBuilder(128);

                handler.WriteToken(XmlWriter.Create(sb), sessionToken);

                return new ContentResult
                {
                    ContentType = "text/xml",
                    Content = sb.ToString()
                };
            }

            return null;
        }

        public ActionResult SessionTokenDecoded()
        {
            var name = User.Identity.Name;
            var claims = ClaimsPrincipal.Current.Identities.FirstOrDefault().Claims.ToList();

            if(!ClaimsPrincipal.Current.HasClaim("role", "Geek"))
                return new HttpUnauthorizedResult();

            var cookieHandler = FederatedAuthentication.SessionAuthenticationModule.CookieHandler;
            var cookieBytes = cookieHandler.Read();
            if (cookieBytes != null && cookieBytes.Length != 0)
            {
                var handler = new SessionSecurityTokenHandler();
                var sam = FederatedAuthentication.SessionAuthenticationModule;
                var sessionToken = sam.ReadSessionTokenFromCookie(cookieBytes);

                var sb = new StringBuilder(128);
                handler.WriteToken(XmlWriter.Create(sb), sessionToken);

                //var xml = XElement.Parse(sb.ToString());
                //var ns = XNamespace.Get("http://schemas.microsoft.com/ws/2006/05/security");
                //byte[] cookieXmlBytes = new SessionSecurityTokenCookieSerializer().Serialize(sessionToken);

                //sb = new StringBuilder();

                //using (XmlDictionaryReader reader = XmlDictionaryReader.CreateBinaryReader(cookieXmlBytes, 0, cookieXmlBytes.Length, SessionDictionary.Instance, XmlDictionaryReaderQuotas.Max, null, null))
                //{
                //    while (reader.Read())
                //    {
                //        sb.AppendLine(reader.ReadOuterXml());
                //    }
                //}

                return new ContentResult
                {
                    ContentType = "text/xml",
                    Content = sb.ToString()
                };
            }

            return null;
        }
    }
}
