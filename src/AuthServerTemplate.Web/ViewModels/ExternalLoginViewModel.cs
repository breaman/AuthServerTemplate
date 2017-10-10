using System.ComponentModel.DataAnnotations;

namespace AuthServerTemplate.Web.ViewModels
{
    public class ExternalLoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}