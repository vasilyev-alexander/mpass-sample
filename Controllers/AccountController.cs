using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Web.Mvc;
using System.Web.Security;
using System.Web.UI;
using System.Xml;
using MPass.Sample.Helpers;
using MPass.Sample.Properties;

namespace MPass.Sample.Controllers
{
    public class AccountController : Controller
    {
        private const string RequestIDSessionKey = "SAML.RequestID";
        private const string SessionIndexSessionKey = "SAML.SessionIndex";
        private readonly Settings settings = Settings.Default;

        // prevent any response caching, as specified by [SAMLBind, 3.5.5.1]
        [OutputCache(Duration = 0, Location = OutputCacheLocation.None, NoStore = true)]
        public ActionResult Login()
        {
            // generate AuthnRequest ID
            var authnRequestID = "_" + Guid.NewGuid();
            Session[RequestIDSessionKey] = authnRequestID;

            // build a full URL to login action
            var fullAcsUrl = Url.Action("Acs", "Account", null, Request.Url.Scheme);

            // build AuthnRequest
            var authnRequest = SamlMessage.BuildAuthnRequest(authnRequestID, settings.SamlLoginDestination, fullAcsUrl, settings.SamlRequestIssuer);

            // sign AuthnRequest
            authnRequest = SamlMessage.Sign(authnRequest, LoadServiceProviderCertificate());

            // redirect to IdP
            ViewBag.IdPUrl = settings.SamlLoginDestination;
            ViewBag.SAMLVariable = "SAMLRequest";
            ViewBag.SAMLMessage = SamlMessage.Encode(authnRequest);
            // NOTE: RelayState must not exceed 80 bytes in length, as specified by [SAMLBind, 3.5.3]
            ViewBag.RelayState = "Sample AuthnRequest Relay State";
            return View("Redirect");
        }

        [HttpPost]
        public ActionResult Acs(string samlResponse, string relayState)
        {            
            XmlNamespaceManager ns;
            string sessionIndex;
            string nameID;
            Dictionary<string, IList<string>> attributes;

            // NOTE: Keeping InResponseTo in an in-memory Session means this verification will always fail if the web app is restarted during a request
            SamlMessage.LoadAndVerifyLoginResponse(samlResponse, LoadIdentityProviderCertificate(), Request.Url.ToString(), settings.SamlMessageTimeout,
                Session[RequestIDSessionKey] as string, settings.SamlRequestIssuer, out ns, out sessionIndex, out nameID, out attributes);

            // remove RequestID from session to stop replay attacks
            Session.Remove(RequestIDSessionKey);
            // save SessionIndex in session
            Session[SessionIndexSessionKey] = sessionIndex;

            TempData["Attributes"] = attributes;
            TempData["RelayState"] = relayState;

            // NOTE: You might want to redirect to ReturnUrl, e.g. by using FormsAuthentication.RedirectFromLoginPage(username, false);
            FormsAuthentication.SetAuthCookie(nameID, false);
            return RedirectToAction("Index", "Home");
        }

        // prevent any response caching, as specified by [SAMLBind, 3.5.5.1]
        [OutputCache(Duration = 0, Location = OutputCacheLocation.None, NoStore = true)]
        [Authorize]
        public ActionResult Logout()
        {
            // generate LogoutRequest ID
            var logoutRequestID = "_" + Guid.NewGuid();

            // build LogoutRequest
            var logoutRequest = SamlMessage.BuildLogoutRequest(logoutRequestID, settings.SamlLogoutDestination, settings.SamlRequestIssuer, 
                User.Identity.Name, Session[SessionIndexSessionKey] as string);

            // sign LogoutRequest
            logoutRequest = SamlMessage.Sign(logoutRequest, LoadServiceProviderCertificate());

            // logout locally
            FormsAuthentication.SignOut();
            Session.Clear();

            Session[RequestIDSessionKey] = logoutRequestID;

            // redirect to IdP
            ViewBag.IdPUrl = settings.SamlLogoutDestination;
            ViewBag.SAMLVariable = "SAMLRequest";
            ViewBag.SAMLMessage = SamlMessage.Encode(logoutRequest);
            // NOTE: RelayState may be maximum 80 bytes, as specified by [SAMLBind, 3.5.3]
            ViewBag.RelayState = "Sample LogoutRequest Relay State";
            return View("Redirect");
        }

        [HttpPost]
        public ActionResult AfterLogout(string samlResponse, string relayState)
        {            
            XmlNamespaceManager ns;

            // NOTE: Keeping InResponseTo in an in-memory Session means this verification will always fail if the web app is restarted during a request
            SamlMessage.LoadAndVerifyLogoutResponse(samlResponse, LoadIdentityProviderCertificate(), Request.Url.ToString(), settings.SamlMessageTimeout, 
                Session[RequestIDSessionKey] as string, out ns);

            // remove SessionIndex from session to stop replay attacks
            Session.Remove(RequestIDSessionKey);

            return RedirectToAction("Index", "Home");
        }

        // prevent any response caching, as specified by [SAMLBind, 3.5.5.1]
        [OutputCache(Duration = 0, Location = OutputCacheLocation.None, NoStore = true)]
        [HttpPost]        
        public ActionResult SingleLogout(string samlRequest, string relayState)
        {
            string logoutRequestID;
            SamlMessage.LoadAndVerifyLogoutRequest(samlRequest, LoadIdentityProviderCertificate(), Request.Url.ToString(), settings.SamlMessageTimeout, 
                User.Identity.Name, Session[SessionIndexSessionKey] as string, out logoutRequestID);

            if (Request.IsAuthenticated)
            {
                // logout locally
                FormsAuthentication.SignOut();
                Session.Abandon();
            }

            // build LogoutResponse
            var logoutResponseID = "_" + Guid.NewGuid();
            var logoutResponse = SamlMessage.BuildLogoutResponse(logoutResponseID, settings.SamlLogoutDestination, logoutRequestID, settings.SamlRequestIssuer);

            // sign LogoutResponse
            logoutResponse = SamlMessage.Sign(logoutResponse, LoadServiceProviderCertificate());

            // redirect to IdP
            ViewBag.IdPUrl = settings.SamlLogoutDestination;
            ViewBag.SAMLVariable = "SAMLResponse";
            ViewBag.SAMLMessage = SamlMessage.Encode(logoutResponse);
            ViewBag.RelayState = relayState;
            return View("Redirect");
        }

        private X509Certificate2 LoadServiceProviderCertificate()
        {
            return new X509Certificate2(Server.MapPath(settings.ServiceCertificate), settings.ServiceCertificatePassword, X509KeyStorageFlags.MachineKeySet);
        }

        private X509Certificate2 LoadIdentityProviderCertificate()
        {
            return new X509Certificate2(Server.MapPath(settings.IdentityProviderCertificate));
        }
    }
}