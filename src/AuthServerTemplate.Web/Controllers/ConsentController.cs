using System.Threading.Tasks;
using AuthServerTemplate.Web.Attributes;
using AuthServerTemplate.Web.Models;
using AuthServerTemplate.Web.Services;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthServerTemplate.Web.Controllers
{
    [SecurityHeaders]
    public class ConsentController : Controller
    {
        private ConsentService ConsentService { get; }
        public ConsentController(
            IIdentityServerInteractionService interactionService,
            IClientStore clientStore,
            IResourceStore resourceStore,
            ILogger<ConsentController> logger)
        {
            ConsentService = new ConsentService(interactionService, clientStore, resourceStore, logger);
        }

        [HttpGet]
        public async Task<IActionResult> Index(string returnUrl)
        {
            IActionResult actionResult = null;

            var vm = await ConsentService.BuildViewModelAsync(returnUrl);
            if (vm != null)
            {
                actionResult = View(vm);
            }
            else
            {
                actionResult = View("Error");
            }

            return actionResult;
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Index(ConsentInputModel model)
        {
            IActionResult actionResult = View("Error");
            var result = await ConsentService.ProcessConsent(model);

            if (result.IsRedirect)
            {
                actionResult = Redirect(result.RedirectUrl);
            }
            else if (result.HasValidationError)
            {
                ModelState.AddModelError("", result.ValidationError);
            }
            else if (result.ShowView)
            {
                actionResult = View(result.ViewModel);
            }

            return actionResult;
        }
    }
}