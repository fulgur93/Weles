using Weles.Core.Enums;
using Weles.Core.Models;
using Weles.Core.Rules;

namespace Weles.Tests.Core;

public class AssetClassifierTests
{
    private static ServiceIdentification Svc(string name, string? os = null, string? device = null)
    {
        var s = new ServiceIdentification { ServiceName = name, Method = "test", OsHint = os };
        if (device is not null) { s.Extra["http.device"] = device; s.Extra["http.panel"] = "panel"; }
        return s;
    }

    private static HostClassification Classify(int[] ports, ServiceIdentification[]? services = null, string? vendor = null, int? ttl = null, bool gateway = false) =>
        AssetClassifier.Classify(new HostEvidence(ports, services ?? [], vendor, ttl, gateway, null));

    [Fact]
    public void Windows_workstation_from_rpc_and_smb()
    {
        var c = Classify([135, 139, 445]);
        Assert.Equal((AssetType.WindowsHost, "Windows"), (c.Type, c.OsFamily));
        Assert.NotEmpty(c.Reasons);
    }

    [Fact]
    public void Windows_domain_controller_is_a_server()
    {
        Assert.Equal(AssetType.Server, Classify([53, 88, 135, 389, 445]).Type);
    }

    [Fact]
    public void Linux_server_from_ssh_banner_and_web()
    {
        var c = Classify([22, 80], [Svc("ssh", "Linux"), Svc("http")]);
        Assert.Equal((AssetType.Server, "Linux"), (c.Type, c.OsFamily));
    }

    [Fact]
    public void Printer_from_jetdirect()
    {
        Assert.Equal(AssetType.Printer, Classify([80, 9100]).Type);
    }

    [Fact]
    public void Camera_from_rtsp()
    {
        Assert.Equal(AssetType.IpCamera, Classify([80, 554], vendor: "Hangzhou Hikvision Digital Technology").Type);
    }

    [Fact]
    public void Gateway_is_a_router()
    {
        Assert.Equal(AssetType.Router, Classify([53, 80], gateway: true).Type);
    }

    [Fact]
    public void Http_device_ui_wins_over_generic_rules()
    {
        Assert.Equal(AssetType.Nas, Classify([5000, 22], [Svc("http", device: "Nas")]).Type);
    }

    [Fact]
    public void Virtual_machine_from_nic_vendor()
    {
        Assert.Equal(AssetType.VirtualMachine, Classify([22], vendor: "VMware").Type);
    }

    [Fact]
    public void Ttl_only_guess_is_labelled_low_confidence()
    {
        var c = Classify([], ttl: 128);
        Assert.Equal("Windows", c.OsFamily);
        Assert.Contains(c.Reasons, r => r.Contains("niska pewność"));
    }

    [Fact]
    public void No_evidence_is_unknown()
    {
        var c = Classify([]);
        Assert.Equal(AssetType.Unknown, c.Type);
        Assert.Equal(0, c.Confidence);
    }

    [Fact]
    public void Local_machine_is_identified_with_its_real_os()
    {
        var c = AssetClassifier.Classify(new HostEvidence([], [], null, null, false, "laptop", IsLocalMachine: true));
        Assert.Contains(c.Reasons, r => r.Contains("WELES"));
        Assert.Equal(OperatingSystem.IsWindows() ? "Windows" : OperatingSystem.IsMacOS() ? "macOS" : "Linux", c.OsFamily);
    }

    [Theory]
    [InlineData("Tenda Technology Co.,Ltd.Dongguan branch", AssetType.NetworkDevice)]
    [InlineData("Advanced Digital Broadcast SA", AssetType.IoTDevice)]
    [InlineData("Frontier Silicon Ltd", AssetType.IoTDevice)]
    public void Vendors_seen_on_a_real_network_are_classified(string vendor, AssetType expected)
    {
        Assert.Equal(expected, Classify([80, 8080], vendor: vendor).Type);
    }

    [Fact]
    public void Randomized_mac_adds_an_explanation_but_no_guess()
    {
        var c = AssetClassifier.Classify(new HostEvidence([], [], null, null, false, null, HasRandomizedMac: true));
        Assert.Equal(AssetType.Unknown, c.Type);
        Assert.Contains(c.Reasons, r => r.Contains("Losowy adres MAC"));
    }

    [Fact]
    public void Upnp_only_device_is_a_low_confidence_iot_guess()
    {
        var svc = new ServiceIdentification { ServiceName = "http", Method = "test" };
        svc.Extra["http.upnp"] = "true";
        var c = Classify([8080], [svc]);
        Assert.Equal(AssetType.IoTDevice, c.Type);
        Assert.True(c.Confidence < 50);
    }
}
