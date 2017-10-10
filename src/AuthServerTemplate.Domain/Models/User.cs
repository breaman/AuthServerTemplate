using System;
using AuthServerTemplate.Domain.Abstract;
using Microsoft.AspNetCore.Identity;

namespace AuthServerTemplate.Domain.Models
{
    public class User : IdentityUser<int>, IEntityBase
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public DateTimeOffset? MemberSince { get; set; }
    }
}