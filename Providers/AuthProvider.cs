using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace HttpAuth.Providers {
    public class AuthProvider : OAuthAuthorizationServerProvider {
        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context) {
            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context) {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            var name = context.UserName;
            var pass = context.Password;
            /*
            using (AuthRepository _repo = new AuthRepository()) {
                IdentityUser user = await _repo.FindUser(context.UserName, context.Password);

                if (user == null) {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }
             * */

         //   return Task.FromResult<object>(null);

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);
            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim("role", "user"));

            context.Validated(identity);
            return Task.FromResult<object>(null);
        }
    }
}