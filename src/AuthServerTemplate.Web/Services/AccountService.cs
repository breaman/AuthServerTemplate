using System.Threading.Tasks;
using AuthServerTemplate.Web.Models;
using AuthServerTemplate.Web.ViewModels;
using IdentityModel;
using IdentityServer4.Extensions;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AuthServerTemplate.Web.Services
{
    public class AccountService
    {
        private IClientStore ClientStore { get; }
        private IIdentityServerInteractionService InteractionService { get; }
        private IHttpContextAccessor HttpContextAccessor { get; }
        private IAuthenticationSchemeProvider SchemeProvider { get; }

        public AccountService(
            IIdentityServerInteractionService interactionService,
            IHttpContextAccessor httpContextAccessor,
            IAuthenticationSchemeProvider schemeProvider,
            IClientStore clientStore)
        {
            InteractionService = interactionService;
            HttpContextAccessor = httpContextAccessor;
            SchemeProvider = schemeProvider;
            ClientStore = clientStore;
        }

        public async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            var user = HttpContextAccessor.HttpContext.User;

            if (user?.Identity.IsAuthenticated != true)
            {
                vm.ShowLogoutPrompt = false;
            }
            else
            {
                var context = await InteractionService.GetLogoutContextAsync(logoutId);
                if (context?.ShowSignoutPrompt == false)
                {
                    vm.ShowLogoutPrompt = false;
                }
            }

            return vm;
        }

        public async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            var logout = await InteractionService.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = logout?.ClientId,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            var user = HttpContextAccessor.HttpContext.User;

            if (user?.Identity.IsAuthenticated == true)
            {
                var idp = user.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportSignout = await HttpContextAccessor.HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await InteractionService.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}