using System.Net;
using PqcKeyRotationProtocol.Config;
using PqcKeyRotationProtocol.Di;
using PqcKeyRotationProtocol.Handshake;

var clientContainer = new DiRegistry().Register(
    new AppConfig(
        ApplicationMode.Client, 
        new IPEndPoint(IPAddress.Loopback, 5000),
        new IPEndPoint(IPAddress.Loopback, 5001)
        ));

var serverContainer = new DiRegistry().Register(new AppConfig(
    ApplicationMode.Server, 
    new IPEndPoint(IPAddress.Loopback, 5000),
    new IPEndPoint(IPAddress.Loopback, 5001)
));

await Task.Delay(200);

var participant = (PqcClient) clientContainer!.GetInstance<IHandshakeParticipant>();
var response = await participant.SendHandshakeAsync();

var serverParticipant = serverContainer!.GetInstance<IHandshakeParticipant>();

Console.WriteLine(
    $"Shared equal: {Convert.ToHexString(response.SharedSecret!) == Convert.ToHexString(serverParticipant.SharedSecret)}");