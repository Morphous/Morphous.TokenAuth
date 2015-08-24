using HttpAuth.Providers;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Orchard.Environment;
using Orchard.Owin;
using Orchard.Security;
using Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace HttpAuth.Owin {
    public class AuthMiddleware : IOwinMiddlewareProvider {
        private readonly Work<IMembershipService> _membershipServiceWork;

        public AuthMiddleware(Work<IMembershipService> membershipServiceWork) {
            _membershipServiceWork = membershipServiceWork;
        }

        public IEnumerable<OwinMiddlewareRegistration> GetOwinMiddlewares() {
            return new[] {
                new OwinMiddlewareRegistration {
                    Priority = "1",
                    Configure = app => {
                        var oAuthOptions = new OAuthAuthorizationServerOptions
                        {
                            TokenEndpointPath = new PathString("/Token"),
                            Provider = new AuthProvider(_membershipServiceWork),
                            AccessTokenExpireTimeSpan = TimeSpan.FromDays(14),
                            AllowInsecureHttp = true
                        };

                        // Enable the application to use bearer tokens to authenticate users
                        app.UseOAuthAuthorizationServer(oAuthOptions);
                        app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
                    }
                }
            };
        }
    }
}