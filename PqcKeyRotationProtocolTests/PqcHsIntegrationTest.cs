using System.Diagnostics;
using System.Net;
using PqcKeyRotationProtocol.Di;
using PqcKeyRotationProtocol.Handshake;
using PqcKeyRotationProtocol.Transport;
using Xunit.Abstractions;

namespace PqcKeyRotationProtocolTests;

public record TunnelConfigHolder
{
    public string? Config { get; init; }
}

public record PqcConfig
{
    public IPEndPoint ClientEp { get; init; } = default!;
    public IPEndPoint ServerEp { get; init; } = default!;
}

public record ConnectionProfile
{
    public TunnelConfigHolder? TunnelConfig { get; init; }
    public PqcConfig PqcConfig { get; init; } = default!;
}

public class PqcHsIntegrationTest(ITestOutputHelper output)
{
    [Fact]
    public async Task Measure_PqcHandshake_And_ConfigRewrite()
    {
        output.WriteLine("=== PQC Handshake + Config Update Timing Test ===");

        //
        // 1. Prepare real PQC container (client + server)
        //

        var clientEp = new IPEndPoint(IPAddress.Loopback, 5000);
        var serverEp = new IPEndPoint(IPAddress.Loopback, 5001);

        var container = PqcContainerFabric.GetClientContainer(clientEp, serverEp);
        var serverContainer = PqcContainerFabric.GetServerContainer(clientEp, serverEp);

        var server = serverContainer.GetInstance<PqcServer>();

        output.WriteLine("PQC server started on 127.0.0.1:5001");

        //
        // 2. Create profile and INI config
        //

        var configString = """
                           [Interface]
                           PrivateKey = TEST_KEY

                           [Peer]
                           PublicKey = TEST_PUB
                           AllowedIPs = 0.0.0.0/0
                           PresharedKey =
                           """;

        var profile = new ConnectionProfile
        {
            TunnelConfig = new TunnelConfigHolder { Config = configString },
            PqcConfig = new PqcConfig { ClientEp = clientEp, ServerEp = serverEp }
        };

        //
        // 3. Execute actual logic of StartConnectingInternal
        //

        var swTotal = Stopwatch.StartNew();

        output.WriteLine("\n--- Step 1: Resolve container components ---");
        var sw1 = Stopwatch.StartNew();

        var handshakeOrchestrator = container.GetInstance<HandshakeOrchestrator>();
        var pqcClient = (PqcClient)container.GetInstance<IHandshakeParticipant>();

        sw1.Stop();
        output.WriteLine($"Container resolution: {sw1.ElapsedMilliseconds} ms");

        //
        // Step 2: Handshake
        //

        output.WriteLine("\n--- Step 2: PQC Handshake ---");
        var sw2 = Stopwatch.StartNew();

        var handshakeResponse = await pqcClient.SendHandshakeAsync();

        sw2.Stop();
        output.WriteLine($"Handshake time: {sw2.ElapsedMilliseconds} ms");

        Assert.NotNull(handshakeResponse.SharedSecret);

        //
        // Step 3: INI parsing
        //

        output.WriteLine("\n--- Step 3: INI parsing & PSK rewrite ---");
        var sw3 = Stopwatch.StartNew();

        var parser = new IniParser.Parser.IniDataParser();
        var data = parser.Parse(configString);
        var peer = data["Peer"];
        var allowed = peer["AllowedIPs"];

        peer["PresharedKey"] = Convert.ToBase64String(handshakeResponse.SharedSecret);

        // emulate AllowedIPs calculator
        peer["AllowedIPs"] = allowed;

        sw3.Stop();
        output.WriteLine($"INI rewrite time: {sw3.ElapsedMilliseconds} ms");

        swTotal.Stop();
        output.WriteLine($"\n=== Total StartConnectingInternal time: {swTotal.ElapsedMilliseconds} ms ===");
    }
}