using System.Text;
using Weles.Core.Models;
using Weles.Core.Rules;

namespace Weles.Tests.Core;

public class BannerParserTests
{
    private static ServiceIdentification Parse(string banner, int port = 0) => BannerParser.Parse(Encoding.ASCII.GetBytes(banner), port)!;

    [Fact]
    public void OpenSsh_with_ubuntu_package_suffix()
    {
        var s = Parse("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10\r\n", 22);

        Assert.Equal("ssh", s.ServiceName);
        Assert.Equal("OpenSSH", s.Product);
        Assert.Equal("8.9p1", s.Version);
        Assert.Equal("cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*", s.Cpe);
        Assert.Equal("Ubuntu", s.DistributionHint);
        Assert.Equal("Linux", s.OsHint);
        Assert.True(s.Confidence >= 90);
    }

    [Fact]
    public void Debian_revision_is_recognised_as_distribution()
    {
        Assert.Equal("Debian", Parse("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3").DistributionHint);
    }

    [Fact]
    public void OpenSsh_for_windows()
    {
        var s = Parse("SSH-2.0-OpenSSH_for_Windows_8.1");
        Assert.Equal(("OpenSSH", "8.1", "Windows"), (s.Product, s.Version, s.OsHint));
    }

    [Fact]
    public void Dropbear_is_embedded_linux()
    {
        var s = Parse("SSH-2.0-dropbear_2020.81");
        Assert.Equal(("Dropbear SSH", "2020.81"), (s.Product, s.Version));
        Assert.StartsWith("Linux", s.OsHint);
    }

    [Fact]
    public void Unknown_ssh_implementation_keeps_name_without_guessing_cpe()
    {
        var s = Parse("SSH-2.0-Cisco-1.25");
        Assert.Equal("ssh", s.ServiceName);
        Assert.Null(s.Cpe);
    }

    [Theory]
    [InlineData("220 (vsFTPd 3.0.3)", "vsftpd", "3.0.3")]
    [InlineData("220 ProFTPD 1.3.5e Server (Debian) [::ffff:10.0.0.5]", "ProFTPD", "1.3.5e")]
    [InlineData("220-FileZilla Server 0.9.60 beta\r\n220 Welcome", "FileZilla Server", "0.9.60 beta")]
    [InlineData("220 Microsoft FTP Service", "Microsoft FTP Service", null)]
    public void Ftp_servers(string banner, string product, string? version)
    {
        var s = Parse(banner, 21);
        Assert.Equal("ftp", s.ServiceName);
        Assert.Equal(product, s.Product);
        Assert.Equal(version, s.Version);
    }

    [Theory]
    [InlineData("220 mail.example.com ESMTP Postfix (Ubuntu)", "Postfix", null)]
    [InlineData("220 mx.example.com ESMTP Exim 4.94.2 Mon, 01 Jan 2024", "Exim", "4.94.2")]
    [InlineData("220 EX01.corp.local Microsoft ESMTP MAIL Service ready", "Microsoft Exchange", null)]
    public void Smtp_is_distinguished_from_ftp(string banner, string product, string? version)
    {
        var s = Parse(banner, 2525);
        Assert.Equal("smtp", s.ServiceName);
        Assert.Equal(product, s.Product);
        Assert.Equal(version, s.Version);
    }

    [Fact]
    public void Generic_220_on_port_25_is_smtp_on_21_is_ftp()
    {
        Assert.Equal("smtp", Parse("220 host ready", 25).ServiceName);
        Assert.Equal("ftp", Parse("220 host ready", 21).ServiceName);
    }

    [Fact]
    public void Pop3_and_imap()
    {
        Assert.Equal(("pop3", "Dovecot"), (Parse("+OK Dovecot (Ubuntu) ready.").ServiceName, Parse("+OK Dovecot (Ubuntu) ready.").Product));
        var imap = Parse("* OK [CAPABILITY IMAP4rev1 SASL-IR] Dovecot ready.");
        Assert.Equal(("imap", "Dovecot"), (imap.ServiceName, imap.Product));
    }

    [Fact]
    public void Vnc_protocol_version()
    {
        var s = Parse("RFB 003.008\n");
        Assert.Equal("vnc", s.ServiceName);
        Assert.Equal("3.8", s.Extra["rfb.version"]);
    }

    [Fact]
    public void Telnet_negotiation_bytes()
    {
        var s = BannerParser.Parse([0xFF, 0xFD, 0x18, 0xFF, 0xFD, 0x20], 23)!;
        Assert.Equal("telnet", s.ServiceName);
    }

    [Fact]
    public void Unrecognised_text_returns_null()
    {
        Assert.Null(Parse("hello there"));
    }

    [Fact]
    public void Banners_are_sanitized_and_truncated()
    {
        var s = BannerParser.Sanitize("abc\u0000\u001b[31mdef" + new string('x', 5000));
        Assert.DoesNotContain('\u0000', s);
        Assert.DoesNotContain('\u001b', s);
        Assert.True(s.Length <= BannerParser.MaxBannerLength);
    }

    private static byte[] MySqlPacket(string version)
    {
        var payload = new List<byte> { 0x0A };
        payload.AddRange(Encoding.ASCII.GetBytes(version));
        payload.Add(0);
        payload.AddRange(new byte[20]);
        return [(byte)payload.Count, 0, 0, 0, .. payload];
    }

    [Fact]
    public void MySql_handshake()
    {
        var s = BannerParser.Parse(MySqlPacket("8.0.36-0ubuntu0.22.04.1"), 3306)!;
        Assert.Equal(("mysql", "MySQL", "8.0.36"), (s.ServiceName, s.Product, s.Version));
        Assert.Equal("cpe:2.3:a:oracle:mysql:8.0.36:*:*:*:*:*:*:*", s.Cpe);
        Assert.Equal("Ubuntu", s.DistributionHint);
    }

    [Fact]
    public void MariaDb_compatibility_prefix_is_removed()
    {
        var s = BannerParser.Parse(MySqlPacket("5.5.5-10.6.12-MariaDB-0ubuntu0.22.04.1"), 3306)!;
        Assert.Equal(("MariaDB", "10.6.12"), (s.Product, s.Version));
    }

    [Fact]
    public void MySql_host_not_allowed_error_packet()
    {
        var msg = Encoding.ASCII.GetBytes("jHost '10.0.0.9' is not allowed to connect to this MySQL server");
        byte[] packet = [(byte)(msg.Length + 3), 0, 0, 0, 0xFF, 0x6A, 0x04, .. msg];
        var s = BannerParser.Parse(packet, 3306)!;
        Assert.Equal("MySQL", s.Product);
        Assert.Null(s.Version);
    }

    [Fact]
    public void Port_only_identification_never_has_product_or_version()
    {
        var s = ServiceIdentification.FromPortOnly(3306);
        Assert.Equal("mysql", s.ServiceName);
        Assert.Null(s.Product);
        Assert.Null(s.Version);
        Assert.True(s.Confidence <= 25);
    }
}
