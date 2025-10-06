
namespace Ecliptix.Domain.Schema.Entities;

public class MobileNumber : EntityBase
{
    public string Number { get; set; } = string.Empty;
    public string? Region { get; set; }

    public virtual ICollection<VerificationFlow> VerificationFlows { get; set; } = new List<VerificationFlow>();
    public virtual ICollection<Membership> Memberships { get; set; } = new List<Membership>();
    public virtual ICollection<MobileDevice> MobileDevices { get; set; } = new List<MobileDevice>();
}