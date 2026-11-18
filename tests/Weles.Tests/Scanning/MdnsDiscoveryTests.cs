using System.Net;
using System.Net.Sockets;
using System.Text;
using Weles.Core.Rules;
using Weles.Infrastructure.Scanning;
using Weles.Tests.Core;
using Weles.Tests.Support;

namespace Weles.Tests.Scanning;

public class MdnsDiscoveryTests
{
    [Fact]
    public async Task Legacy_unicast_query_collects_announced_services_per_host()
    {
        using var responder = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)responder.Client.LocalEndPoint!).Port;
        var questions = new List<string>();
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var server = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                UdpReceiveResult query;
                try { query = await responder.ReceiveAsync(cts.Token); } catch (OperationCanceledException) { return; }
                lock (questions) questions.Add(Encoding.ASCII.GetString(query.Buffer));
                var id = (ushort)(query.Buffer[0] << 8 | query.Buffer[1]);
                var reply = DnsTestPackets.Response(id,
                    DnsTestPackets.Ptr("_adb-tls-connect._tcp.local", "adb-XIAOMI._adb-tls-connect._tcp.local"),
                    DnsTestPackets.Srv("adb-XIAOMI._adb-tls-connect._tcp.local", 41234, "Android-2.local"),
                    DnsTestPackets.Txt("adb-XIAOMI._adb-tls-connect._tcp.local", "v=ADB_SECURE_SERVICE_VERSION"),
                    DnsTestPackets.A("Android-2.local", "127.0.0.1"));
                await responder.SendAsync(reply, query.RemoteEndPoint, cts.Token);
            }
        });

        var hosts = await MdnsDiscovery.DiscoverAsync([IPAddress.Loopback], 800, CancellationToken.None, new IPEndPoint(IPAddress.Loopback, port));
        await cts.CancelAsync();
        await server;

        var host = hosts[IPAddress.Loopback];
        Assert.Equal("android-2.local", host.Hostname);
        var svc = Assert.Single(host.Services);
        Assert.Equal(("_adb-tls-connect._tcp", "adb-XIAOMI", 41234), (svc.Type, svc.Instance, svc.Port));
        Assert.Contains(questions, q => q.Contains("_services"));
    }

    [Fact]
    public async Task No_responders_yields_empty_result_without_error()
    {
        using var silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var hosts = await MdnsDiscovery.DiscoverAsync([IPAddress.Loopback], 300, CancellationToken.None, (IPEndPoint)silent.Client.LocalEndPoint!);
        Assert.Empty(hosts);
    }

    [Fact]
    public void Mdns_hint_names_a_service_that_did_not_identify_itself()
    {
        var weak = Weles.Core.Models.ServiceIdentification.FromPortOnly(41234);
        var hinted = ScanEngine.WithMdnsHint(weak, new MdnsService("_adb-tls-connect._tcp", "adb-XIAOMI", 41234, []));

        Assert.Equal("adb-tls", hinted.ServiceName);
        Assert.Equal("Android", hinted.OsHint);
        Assert.Equal("true", hinted.Extra["mdns.risky"]);
        Assert.Null(hinted.Version); // an announcement does not reveal a version
        Assert.EndsWith("+mdns", hinted.Method);
    }

    [Fact]
    public void Strong_identification_is_not_overridden_by_an_announcement()
    {
        var ssh = new Weles.Core.Models.ServiceIdentification { ServiceName = "ssh", Product = "OpenSSH", Method = "banner", Confidence = 95 };
        var hinted = ScanEngine.WithMdnsHint(ssh, new MdnsService("_sftp-ssh._tcp", "nas", 22, []));
        Assert.Equal(("ssh", "banner"), (hinted.ServiceName, hinted.Method));
        Assert.Equal("SFTP", hinted.Extra["mdns.service"]);
    }
}

public class AdbProbeTests
{
    [Fact]
    public async Task Adb_probe_reads_auth_challenge_and_sends_nothing_else()
    {
        var received = new List<byte[]>();
        await using var server = FakeServer.RequestResponse(req =>
        {
            lock (received) received.Add(req);
            return AdbHandshakeTests.Message("AUTH", new string('t', 20));
        });

        var prober = new ServiceProber(new ScanOptions { ConnectTimeoutMs = 1000, ProbeTimeoutMs = 1000 });
        var id = await prober.ProbeProtocolAsync("adb", IPAddress.Loopback, server.Port, CancellationToken.None);

        Assert.Equal("required", id!.Extra["adb.auth"]);
        Assert.Single(received); // only CNXN – the AUTH challenge is never answered, so no prompt appears on the phone
        Assert.Equal("CNXN", Encoding.ASCII.GetString(received[0], 0, 4));
    }
}
