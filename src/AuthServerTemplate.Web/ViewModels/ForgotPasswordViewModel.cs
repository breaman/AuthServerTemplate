using System.ComponentModel.DataAnnotations;

namespace AuthServerTemplate.Web.ViewModels
{
    public class ForgotPasswordViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}