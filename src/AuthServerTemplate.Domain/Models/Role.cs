using AuthServerTemplate.Domain.Abstract;
using Microsoft.AspNetCore.Identity;

namespace AuthServerTemplate.Domain.Models
{
    public class Role : IdentityRole<int>, IEntityBase {}
}