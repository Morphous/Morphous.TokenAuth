using HttpAuth.TransferModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Web.Http;

namespace HttpAuth.Controllers {
    [Authorize]
    public class AccountController : ApiController {
        public string Get() {

            return "test";
        }

        [AllowAnonymous]
        [HttpPost]
        public IHttpActionResult Register(RegisterBindingModel model) {
            if (model == null) {
                return BadRequest();
            }

            if (!ModelState.IsValid) {
                return BadRequest(ModelState);
            }

            return Ok();
        }
    }
}
