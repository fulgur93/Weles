namespace Weles.Core.Networking;

/// <summary>
/// Conventional service names per port. Used only as a low-confidence hint –
/// a port number never implies a product or a version.
/// </summary>
public static class WellKnownPorts
{
    private static readonly Dictionary<int, string> Names = new()
    {
        [7] = "echo", [9] = "discard", [13] = "daytime", [20] = "ftp-data", [21] = "ftp", [22] = "ssh", [23] = "telnet",
        [25] = "smtp", [37] = "time", [53] = "dns", [79] = "finger", [80] = "http", [81] = "http", [88] = "kerberos",
        [110] = "pop3", [111] = "rpcbind", [113] = "ident", [119] = "nntp", [135] = "msrpc", [137] = "netbios-ns",
        [139] = "netbios-ssn", [143] = "imap", [161] = "snmp", [179] = "bgp", [389] = "ldap", [427] = "svrloc",
        [443] = "https", [444] = "https", [445] = "microsoft-ds", [464] = "kpasswd", [465] = "smtps", [513] = "rlogin",
        [514] = "rsh", [515] = "printer", [548] = "afp", [554] = "rtsp", [587] = "submission", [593] = "http-rpc-epmap",
        [631] = "ipp", [636] = "ldaps", [873] = "rsync", [902] = "vmware-auth", [990] = "ftps", [993] = "imaps",
        [995] = "pop3s", [1080] = "socks", [1234] = "http", [1716] = "kdeconnect", [2121] = "ftp", [2221] = "ftp", [5037] = "adb-server", [5555] = "adb",
        [7000] = "airplay", [8022] = "ssh", [8889] = "http", [12345] = "http", [62078] = "iphone-sync", [1194] = "openvpn", [1433] = "mssql", [1521] = "oracle", [1720] = "h323",
        [1723] = "pptp", [1883] = "mqtt", [1900] = "upnp", [2049] = "nfs", [2082] = "cpanel", [2083] = "cpanel-ssl",
        [2181] = "zookeeper", [2222] = "ssh", [2375] = "docker", [2376] = "docker-tls", [3000] = "http", [3128] = "http-proxy",
        [3268] = "globalcatalog", [3306] = "mysql", [3389] = "rdp", [3690] = "svn", [4443] = "https", [5000] = "http",
        [5001] = "https", [5060] = "sip", [5061] = "sips", [5353] = "mdns", [5432] = "postgresql", [5601] = "kibana",
        [5672] = "amqp", [5800] = "vnc-http", [5900] = "vnc", [5901] = "vnc", [5985] = "winrm", [5986] = "winrm-tls",
        [6000] = "x11", [6379] = "redis", [6443] = "kubernetes-api", [6667] = "irc", [7001] = "http", [7443] = "https",
        [7547] = "tr-069", [8000] = "http", [8008] = "http", [8009] = "ajp", [8080] = "http-proxy", [8081] = "http",
        [8086] = "influxdb", [8088] = "http", [8181] = "http", [8291] = "winbox", [8443] = "https-alt", [8530] = "wsus",
        [8834] = "nessus", [8888] = "http", [9000] = "http", [9090] = "http", [9091] = "http", [9100] = "jetdirect",
        [9200] = "elasticsearch", [9443] = "https", [10000] = "webmin", [10250] = "kubelet", [11211] = "memcached",
        [15672] = "rabbitmq-mgmt", [27017] = "mongodb", [32400] = "plex"
    };

    /// <summary>Ports that usually speak TLS immediately after connecting.</summary>
    public static readonly IReadOnlySet<int> ImplicitTlsPorts = new HashSet<int>
    {
        443, 444, 465, 636, 990, 993, 995, 2083, 2376, 4443, 5001, 5061, 5986, 6443, 7443, 8443, 9443, 10250
    };

    public static string? NameOf(int port) => Names.GetValueOrDefault(port);
}
