using System.Threading.Tasks;
using AuthServerTemplate.Web.Attributes;
using AuthServerTemplate.Web.ViewModels;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Mvc;

namespace AuthServerTemplate.Web.Controllers
{
    [SecurityHeaders]
    public class HomeController : Controller
    {
        private IIdentityServerInteractionService InteractionService { get; }
        public HomeController(IIdentityServerInteractionService interactionService)
        {
            InteractionService = interactionService;
        }
        public IActionResult Index()
        {
            return View();
        }
        public async Task<IActionResult> Error(string errorId)
        {
            var vm = new ErrorViewModel();

            var message = await InteractionService.GetErrorContextAsync(errorId);
            if (message != null)
            {
                vm.Error = message;
            }

            return View(vm);
        }
    }
}