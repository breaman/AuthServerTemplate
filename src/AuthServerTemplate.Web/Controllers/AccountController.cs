using System;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthServerTemplate.Domain.Models;
using AuthServerTemplate.Web.Attributes;
using AuthServerTemplate.Web.Extensions;
using AuthServerTemplate.Web.Models;
using AuthServerTemplate.Web.Services;
using AuthServerTemplate.Web.ViewModels;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace AuthServerTemplate.Web.Controllers
{
    [Authorize]
    [SecurityHeaders]
    public class AccountController : Controller
    {
        private UserManager<User> UserManager { get; }
        private SignInManager<User> SignInManager { get; }
        private ILogger Logger { get; }
        private IIdentityServerInteractionService InteractionService { get; }
        private AccountService AccountService { get; }

        public AccountController(
            UserManager<User> userManager,
            SignInManager<User> signInManager,
            ILogger<AccountController> logger,
            IIdentityServerInteractionService interactionService,
            IClientStore clientStore,
            IHttpContextAccessor httpContextAccessor,
            IAuthenticationSchemeProvider schemeProvider
        )
        {
            UserManager = userManager;
            SignInManager = signInManager;
            Logger = logger;

            InteractionService = interactionService;
            AccountService = new AccountService(interactionService, httpContextAccessor, schemeProvider, clientStore);
        }

        [TempData]
        public string ErrorMessage { get; set; }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            IActionResult actionResult = View(model);

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await SignInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    Logger.LogInformation("User logged in.");
                    actionResult = RedirectToLocal(returnUrl);
                }
                else if (result.RequiresTwoFactor)
                {
                    actionResult = RedirectToAction(nameof(LoginWith2fa), new { returnUrl, model.RememberMe });
                }
                else if (result.IsLockedOut)
                {
                    Logger.LogWarning("User account locked out.");
                    actionResult = RedirectToAction(nameof(Lockout));
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                }
            }

            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWith2fa(bool rememberMe, string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user == null)
            {
                throw new ApplicationException("Unable to load two-factor authentication user");
            }

            var model = new LoginWith2faViewModel { RememberMe = rememberMe };
            ViewBag.ReturnUrl = returnUrl;

            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWith2fa(LoginWith2faViewModel model, bool rememberMe, string returnUrl = null)
        {
            IActionResult actionResult = View(model);

            if (ModelState.IsValid)
            {
                var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();
                if (user == null)
                {
                    throw new ApplicationException($"Unable to load user with ID '{UserManager.GetUserId(User)}'.");
                }

                var authenticationCode = model.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);
                var result = await SignInManager.TwoFactorAuthenticatorSignInAsync(authenticationCode, rememberMe, model.RememberMachine);

                if (result.Succeeded)
                {
                    Logger.LogInformation("User with ID {UserId} logged in with 2fa", user.Id);
                    actionResult = RedirectToLocal(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    Logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                    actionResult = RedirectToAction(nameof(Lockout));
                }
                else
                {
                    Logger.LogWarning("Invalid authenticator code entered for user with ID {UserId}.", user.Id);
                    ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
                }
            }

            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> LoginWithRecoveryCode(string returnUrl = null)
        {
            // Ensure the user has gone through the username & password screen first
            var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
            {
                throw new ApplicationException("Unable to load two-factor authentication user");
            }

            ViewBag.ReturnUrl = returnUrl;

            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> LoginWithRecoveryCode(LoginWithRecoveryCodeViewModel model, string returnUrl = null)
        {
            IActionResult actionResult = View(model);

            if (ModelState.IsValid)
            {
                var user = await SignInManager.GetTwoFactorAuthenticationUserAsync();
                if (user == null)
                {
                    throw new ApplicationException("Unable to load two-factor authentication user.");
                }

                var recoveryCode = model.RecoveryCode.Replace(" ", string.Empty);

                var result = await SignInManager.TwoFactorRecoveryCodeSignInAsync(recoveryCode);

                if (result.Succeeded)
                {
                    Logger.LogInformation("User with ID {UserId} logged in with a recovery code.", user.Id);
                    actionResult = RedirectToLocal(returnUrl);
                }
                else if (result.IsLockedOut)
                {
                    Logger.LogWarning("User with ID {UserId} account locked out.", user.Id);
                    actionResult = RedirectToAction(nameof(Lockout));
                }
                else
                {
                    Logger.LogWarning("Invalid recovery code entered for user with ID {UserId}.", user.Id);
                    ModelState.AddModelError(string.Empty, "Invalid recovery code entered.");
                }
            }

            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register(string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model, string returnUrl = null)
        {
            ViewBag.ReturnUrl = returnUrl;
            IActionResult actionResult = View(model);

            if (ModelState.IsValid)
            {
                var user = new User { UserName = model.Email, Email = model.Email, FirstName = model.FirstName, LastName = model.LastName, MemberSince = DateTimeOffset.Now };
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    Logger.LogInformation("User created a new account with password.");

                    var code = await UserManager.GenerateEmailConfirmationTokenAsync(user);
                    var callbackUrl = Url.EmailConfirmationLink(user.Id, code, Request.Scheme);
                    // should send email here

                    await SignInManager.SignInAsync(user, isPersistent: false);
                    Logger.LogInformation("User created a new account with password.");
                    actionResult = RedirectToLocal(returnUrl);
                }
                else
                {
                    AddErrors(result);
                }
            }

            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await AccountService.BuildLogoutViewModelAsync(logoutId);
            IActionResult actionResult = View(vm);

            if (!vm.ShowLogoutPrompt)
            {
                // if the request for logout was property authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                actionResult = await Logout(vm);
            }

            return actionResult;
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            var vm = await AccountService.BuildLoggedOutViewModelAsync(model.LogoutId);
            IActionResult actionResult = View("LoggedOut", vm);

            await SignInManager.SignOutAsync();
            Logger.LogInformation("User logged out.");

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. This allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                // hack: try/catch to handle social providers that throw
                actionResult = SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            return actionResult;
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            // Request a redirect to the external login provider.
            var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Account", new { returnUrl });
            var properties = SignInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
            return Challenge(properties, provider);
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
        {
            IActionResult actionResult = null;

            if (remoteError != null)
            {
                ErrorMessage = $"Error from external provider: {remoteError}";
                actionResult = RedirectToAction(nameof(Login));
            }
            else
            {
                var info = await SignInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    actionResult = RedirectToAction(nameof(Login));
                }
                else
                {
                    // Sign in the user with this external login provider if the user already has a login.
                    var result = await SignInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false, bypassTwoFactor: true);
                    if (result.Succeeded)
                    {
                        Logger.LogInformation("User logged in with {Name} provider.", info.LoginProvider);
                        actionResult = RedirectToLocal(returnUrl);
                    }
                    else if (result.IsLockedOut)
                    {
                        actionResult = RedirectToAction(nameof(Lockout));
                    }
                    else
                    {
                        // If the user does not have an account, then ask the user to create an account.
                        ViewBag.ReturnUrl = returnUrl;
                        ViewBag.LoginProvider = info.LoginProvider;
                        var email = info.Principal.FindFirstValue(ClaimTypes.Email);

                        actionResult = View("ExternalLogin", new ExternalLoginViewModel { Email = email });
                    }
                }
            }

            return actionResult;
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ExternalLoginConfirmation(ExternalLoginViewModel model, string returnUrl = null)
        {
            IActionResult actionResult = View(nameof(ExternalLogin), model);

            if (ModelState.IsValid)
            {
                // Get the information about the user from the external login provider
                var info = await SignInManager.GetExternalLoginInfoAsync();
                if (info == null)
                {
                    throw new ApplicationException("Error loading external login information during confirmation.");
                }

                var user = new User { UserName = model.Email, Email = model.Email, FirstName = "", LastName = "", MemberSince = DateTimeOffset.Now };
                var result = await UserManager.CreateAsync(user);

                if (result.Succeeded)
                {
                    result = await UserManager.AddLoginAsync(user, info);
                    if (result.Succeeded)
                    {
                        await SignInManager.SignInAsync(user, isPersistent: false);
                        Logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);
                        actionResult = RedirectToLocal(returnUrl);
                    }
                    else
                    {
                        AddErrors(result);
                    }
                }
                else
                {
                    AddErrors(result);
                }
            }

            ViewBag.ReturnUrl = returnUrl;
            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string code)
        {
            IActionResult actionResult = null;

            if (userId == null || code == null)
            {
                actionResult = RedirectToAction(nameof(HomeController.Index), "Home");
            }
            else
            {
                var user = await UserManager.FindByIdAsync(userId);
                if (user == null)
                {
                    throw new ApplicationException($"Unable to load user with ID '{userId}'.");
                }

                var result = await UserManager.ConfirmEmailAsync(user, code);
                actionResult = View(result.Succeeded ? "ConfirmEmail" : "Error");
            }

            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            IActionResult actionResult = View(model);

            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByEmailAsync(model.Email);
                if (user == null || !(await UserManager.IsEmailConfirmedAsync(user)))
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    actionResult = RedirectToAction(nameof(ForgotPasswordConfirmation));
                }
                else
                {
                    // For mor information on how to enable account confirmation and password reset please
                    // visit https://go.microsoft.com/fwlink/?LinkID=532713
                    var code = await UserManager.GeneratePasswordResetTokenAsync(user);
                    var callbackUrl = Url.ResetPasswordCallbackLink(user.Id, code, Request.Scheme);
                    // need to send email
                    actionResult = RedirectToAction(nameof(ForgotPasswordConfirmation));
                }
            }

            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ForgotPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPassword(string code = null)
        {
            if (code == null)
            {
                throw new ApplicationException("A code must be supplied for password reset.");
            }

            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            IActionResult actionResult = View(model);
            if (ModelState.IsValid)
            {
                var user = await UserManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    // Don't reveal that the user doesn't exist
                    actionResult = RedirectToAction(nameof(ResetPasswordConfirmation));
                }
                else
                {
                    var result = await UserManager.ResetPasswordAsync(user, model.Code, model.Password);
                    if (result.Succeeded)
                    {
                        actionResult = RedirectToAction(nameof(ResetPasswordConfirmation));
                    }
                    else
                    {
                        AddErrors(result);
                        actionResult = View();
                    }
                }
            }

            return actionResult;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult ResetPasswordConfirmation()
        {
            return View();
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }

        #region Helpers
        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError(string.Empty, error.Description);
            }
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            IActionResult actionResult = null;

            if (Url.IsLocalUrl(returnUrl))
            {
                actionResult = Redirect(returnUrl);
            }
            else
            {
                actionResult = RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return actionResult;
        }
        #endregion
    }
}