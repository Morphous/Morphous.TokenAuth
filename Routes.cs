using Orchard.Mvc.Routes;
using Orchard.WebApi.Routes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Http;

namespace Morphous.TokenAuth {
    public class HttpRoutes : IHttpRouteProvider {

        public void GetRoutes(ICollection<RouteDescriptor> routes) {
            foreach (var routeDescriptor in GetRoutes()) {
                routes.Add(routeDescriptor);
            }
        }

        public IEnumerable<RouteDescriptor> GetRoutes() {
            return new[] {
                new HttpRouteDescriptor {
                    Priority = 5,
                    RouteTemplate = "api/account/{action}/{id}",
                    Defaults = new {
                        area = "Morphous.TokenAuth",
                        controller = "Account",
                        id = RouteParameter.Optional
                    }
                }
            };
        }
    }
}