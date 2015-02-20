/*
 * Copyright (c) Dominick Baier.  All rights reserved.
 * 
 * This code is licensed under the Microsoft Permissive License (Ms-PL)
 * 
 * SEE: http://www.microsoft.com/resources/sharedsource/licensingbasics/permissivelicense.mspx
 * 
 */

using System;
using System.Web.Mvc;

namespace Thinktecture.IdentityModel.Web
{
    public class UnauthorizedResult : ActionResult
    {
        int _statusCode = 401;
        string _scheme;
        ResponseAction _responseAction = ResponseAction.Send401;

        public enum ResponseAction
        {
            Send401,
            RedirectToLoginPage
        }

        public UnauthorizedResult()
            : this("", ResponseAction.Send401)
        { }

        public UnauthorizedResult(string scheme)
            : this (scheme, ResponseAction.Send401)
        { }

        public UnauthorizedResult(string scheme, ResponseAction responseAction)
        {
            _scheme = scheme;
            _responseAction = responseAction;
        }

        public override void ExecuteResult(ControllerContext context)
        {
            if (context == null)
            {
                throw new ArgumentNullException("context");
            }

            if (_responseAction == ResponseAction.Send401)
            {
                if (!string.IsNullOrWhiteSpace(_scheme))
                {
                    context.HttpContext.Response.Headers.Add("WWW-Authenticate", _scheme);
                }

                context.HttpContext.Items["NoRedirect"] = true;
            }

            context.HttpContext.Response.StatusCode = _statusCode;
        }
    }
}