using AuthServerTemplate.Web.Models;

namespace AuthServerTemplate.Web.ViewModels
{
    public class LogoutViewModel : LogoutInputModel
    {
        public bool ShowLogoutPrompt { get; set; }
    }
}