using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthServerTemplate.Web.Attributes;
using AuthServerTemplate.Web.ViewModels;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthServerTemplate.Web.Controllers
{
    [SecurityHeaders]
    [Authorize(AuthenticationSchemes = IdentityServer4.IdentityServerConstants.DefaultCookieAuthenticationScheme)]
    public class GrantsController : Controller
    {
        private IIdentityServerInteractionService InteractionService { get; }
        private IClientStore ClientStore { get; }
        private IResourceStore ResourceStore { get; }

        public GrantsController(IIdentityServerInteractionService interactionService,
            IClientStore clientStore,
            IResourceStore resourceStore)
        {
            InteractionService = interactionService;
            ClientStore = clientStore;
            ResourceStore = resourceStore;
        }

        [HttpGet]
        public async Task<IActionResult> Index()
        {
            return View(await BuildViewModelAsync());
        }

        private async Task<GrantsViewModel> BuildViewModelAsync()
        {
            var grants = await InteractionService.GetAllUserConsentsAsync();

            var list = new List<GrantViewModel>();
            foreach(var grant in grants)
            {
                var client = await ClientStore.FindClientByIdAsync(grant.ClientId);
                if (client != null)
                {
                    var resources = await ResourceStore.FindResourcesByScopeAsync(grant.Scopes);

                    var item = new GrantViewModel()
                    {
                        ClientId = client.ClientId,
                        ClientName = client.ClientName ?? client.ClientId,
                        ClientLogoUrl = client.LogoUri,
                        ClientUrl = client.ClientUri,
                        Created = grant.CreationTime,
                        Expires = grant.Expiration,
                        IdentityGrantNames = resources.IdentityResources.Select(x => x.DisplayName ?? x.Name).ToArray(),
                        ApiGrantNames = resources.ApiResources.Select(x => x.DisplayName ?? x.Name).ToArray()
                    };

                    list.Add(item);
                }
            }

            return new GrantsViewModel
            {
                Grants = list
            };
        }
    }
}