using AuthServerTemplate.Web.ViewModels;

namespace AuthServerTemplate.Web.Models
{
    public class ProcessConsentResult
    {
        public bool IsRedirect => RedirectUrl != null;
        public string RedirectUrl { get; set; }
        public bool ShowView => ViewModel != null;
        public ConsentViewModel ViewModel { get; set; }

        public bool HasValidationError => ValidationError != null;
        public string ValidationError { get; set; }
    }
}