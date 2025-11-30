using System.Diagnostics;
using System.Net;
using PqcKeyRotationProtocol.Crypto;
using PqcKeyRotationProtocol.Di;
using PqcKeyRotationProtocol.Handshake;
using PqcKeyRotationProtocol.Net;
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
    // реальный AWS endpoint, на котором у тебя крутится сервер
    private const string AwsHost = "16.16.72.232";
    private const int AwsPort = 8443;

    private IPEndPoint AwsServerEp => new(IPAddress.Parse(AwsHost), AwsPort);

    // -------------------------------------------------------------------------
    // 1) Full PQC key-update cycle
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Measure_Full_Key_Update_Cycle()
    {
        output.WriteLine($"Remote PQC server: {AwsHost}:{AwsPort}");
        output.WriteLine("=== Full Key Update Timing Test ===");
        
        var clientEp = new IPEndPoint(IPAddress.Loopback, 5000);
        
        var clientContainer = PqcContainerFabric.GetClientContainer(clientEp, AwsServerEp);
        var clientOrchestrator = clientContainer.GetInstance<HandshakeOrchestrator>();

        var configString = """
                           [Interface]
                           PrivateKey = TEST_KEY

                           [Peer]
                           PublicKey = TEST_PUB
                           AllowedIPs = 0.0.0.0/0
                           PresharedKey =
                           """;

        var swTotal = Stopwatch.StartNew();
        
        var sw1 = Stopwatch.StartNew();
        var pqcClient = (PqcClient)clientContainer.GetInstance<IHandshakeParticipant>();
        sw1.Stop();
        output.WriteLine($"Container resolution: {sw1.ElapsedMilliseconds} ms");
        
        var sw2 = Stopwatch.StartNew();
        var hs = await pqcClient.SendHandshakeAsync();
        sw2.Stop();
        output.WriteLine($"Handshake: {sw2.ElapsedMilliseconds} ms");

        Assert.NotNull(hs.SharedSecret);
        
        var sw3 = Stopwatch.StartNew();
        var parser = new IniParser.Parser.IniDataParser();
        var data = parser.Parse(configString);
        var peer = data["Peer"];
        peer["PresharedKey"] = Convert.ToBase64String(hs.SharedSecret);
        sw3.Stop();
        output.WriteLine($"Config rewrite: {sw3.ElapsedMilliseconds} ms");

        swTotal.Stop();
        output.WriteLine($"\n=== Total: {swTotal.ElapsedMilliseconds} ms ===");
        
        clientOrchestrator.Stop();
    }

    // -------------------------------------------------------------------------
    // 2) Kyber KeyGen
    // -------------------------------------------------------------------------
    [Fact]
    public void Measure_Kyber768_KeyGen_Time()
    {
        output.WriteLine($"Remote PQC server: {AwsHost}:{AwsPort}");
        output.WriteLine("=== Kyber-768 KeyGen Timing Test ===");

        var kem = new CrystalsKyberWrapper();

        var sw = Stopwatch.StartNew();
        var kp = kem.GenerateKeyPair();
        sw.Stop();

        output.WriteLine($"KeyGen time: {sw.ElapsedMilliseconds} ms");
        output.WriteLine($"PublicKey size: {kp.PublicKey.Length} bytes");
        output.WriteLine($"PrivateKey size: {kp.PrivateKey.Length} bytes");
    }

    // -------------------------------------------------------------------------
    // 3) Encapsulate/Decapsulate
    // -------------------------------------------------------------------------
    [Fact]
    public void Measure_Kyber768_KEM_Time()
    {
        output.WriteLine($"Remote PQC server: {AwsHost}:{AwsPort}");
        output.WriteLine("=== Kyber-768 KEM Operations Timing Test ===");

        var kem = new CrystalsKyberWrapper();
        var kp = kem.GenerateKeyPair();

        var sw1 = Stopwatch.StartNew();
        var enc = kem.Encapsulate(kp.PublicKey);
        sw1.Stop();
        output.WriteLine($"Encapsulate: {sw1.ElapsedMilliseconds} ms");

        var sw2 = Stopwatch.StartNew();
        var ss2 = kem.Decapsulate(kp.PrivateKey, enc.CipherText);
        sw2.Stop();
        output.WriteLine($"Decapsulate: {sw2.ElapsedMilliseconds} ms");

        Assert.True(CrystalsKyberWrapper.SecretsEqual(enc.SharedSecret, ss2));
    }

    // -------------------------------------------------------------------------
    // 4) PQC handshake (отдельно)
    // -------------------------------------------------------------------------
    [Fact]
    public async Task Measure_PqcHandshake_Time()
    {
        output.WriteLine($"Remote PQC server: {AwsHost}:{AwsPort}");
        output.WriteLine("=== PQC Handshake Timing Test ===");

        var clientEp = new IPEndPoint(IPAddress.Loopback, 5000);

        var clientContainer = PqcContainerFabric.GetClientContainer(clientEp, AwsServerEp);
        var clientOrchestrator = clientContainer.GetInstance<HandshakeOrchestrator>();
        
        var pqcClient = (PqcClient)clientContainer.GetInstance<IHandshakeParticipant>();

        var sw = Stopwatch.StartNew();
        var response = await pqcClient.SendHandshakeAsync();
        sw.Stop();

        output.WriteLine($"Handshake time: {sw.ElapsedMilliseconds} ms");

        Assert.NotNull(response.SharedSecret);
        
        clientOrchestrator.Stop();
    }

    // -------------------------------------------------------------------------
    // 5) INI rewrite
    // -------------------------------------------------------------------------
    [Fact]
    public void Measure_ConfigRewrite_Time()
    {
        output.WriteLine($"Remote PQC server: {AwsHost}:{AwsPort}");
        output.WriteLine("=== INI Rewrite Timing Test ===");

        var configString = """
                           [Interface]
                           PrivateKey = TEST_KEY

                           [Peer]
                           PublicKey = TEST_PUB
                           AllowedIPs = 0.0.0.0/0
                           PresharedKey =
                           """;

        var fakeSecret = new byte[32];
        Random.Shared.NextBytes(fakeSecret);

        var sw = Stopwatch.StartNew();

        var parser = new IniParser.Parser.IniDataParser();
        var data = parser.Parse(configString);
        data["Peer"]["PresharedKey"] = Convert.ToBase64String(fakeSecret);

        sw.Stop();

        output.WriteLine($"INI rewrite time: {sw.ElapsedMilliseconds} ms");
    }

    // -------------------------------------------------------------------------
    // 6) AllowedIPs calc
    // -------------------------------------------------------------------------
    [Fact]
    public void Measure_AllowedIPs_Calc_Time()
    {
        output.WriteLine($"Remote PQC server: {AwsHost}:{AwsPort}");
        output.WriteLine("=== AllowedIPs Calculation Timing Test ===");

        var calc = new AllowedIpsCalculator();

        var sw = Stopwatch.StartNew();
        var result = calc.Calculate("0.0.0.0/0", "10.0.0.1/32");
        sw.Stop();

        output.WriteLine($"AllowedIPs calc time: {sw.ElapsedMilliseconds} ms");
        output.WriteLine($"Result: {result}");
    }
}
