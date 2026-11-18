using Weles.Core.Entities;
using Weles.Core.Enums;

namespace Weles.Tests.Support;

public static class TestData
{
    public static readonly DateTime Now = new(2026, 11, 18, 12, 0, 0, DateTimeKind.Utc);

    public static ScanTarget ApprovedTarget(string name = "LAN") => new()
    {
        Name = name,
        IsApproved = true,
        ApprovedAt = Now,
        CreatedAt = Now,
        Entries = [new ScanTargetEntry { Value = "192.168.1.0/24", Kind = ScanTargetEntryKind.Cidr }]
    };

    public static Scan CompletedScan(ScanTarget target, DateTime started) => new()
    {
        ScanTarget = target,
        Status = ScanStatus.Completed,
        PortSpecification = "top100",
        CreatedAt = started,
        StartedAt = started,
        CompletedAt = started.AddMinutes(3)
    };
}
