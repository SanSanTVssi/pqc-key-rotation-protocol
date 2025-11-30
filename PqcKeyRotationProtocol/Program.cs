using PqcKeyRotationProtocol.Config;
using PqcKeyRotationProtocol.Di;
using PqcKeyRotationProtocol.Handshake;
using PqcKeyRotationProtocol.Transport;

var clientContainer = new DiRegistry().Register(ApplicationMode.Client);
var serverContainer = new DiRegistry().Register(ApplicationMode.Server);

await Task.Delay(200);

var participant = (PqcClient) clientContainer!.GetInstance<IHandshakeParticipant>();
var response = await participant.SendHandshakeAsync();

var serverParticipant = serverContainer!.GetInstance<IHandshakeParticipant>();

Console.WriteLine(
    $"Shared equal: {Convert.ToHexString(response.SharedSecret!) == Convert.ToHexString(serverParticipant.SharedSecret)}");