using PqcKeyRotationProtocol.Config;
using PqcKeyRotationProtocol.Di;
using PqcKeyRotationProtocol.Handshake;
using PqcKeyRotationProtocol.Transport;
using SimpleInjector;

var clientContainer = new DiRegistry().Register(ApplicationMode.Client);
var serverContainer = new DiRegistry().Register(ApplicationMode.Server);

var server = serverContainer.GetInstance<HandshakeOrchestrator>();
var client = clientContainer.GetInstance<HandshakeOrchestrator>();

_ = server.StartAsync();
_ = client.StartAsync();

await Task.Delay(200);

var participant = (PqcClient) clientContainer.GetInstance<IHandshakeParticipant>();
participant.Start();

await Task.Delay(1000);

var serverParticipant = serverContainer.GetInstance<IHandshakeParticipant>();
var clientParticipant = clientContainer.GetInstance<IHandshakeParticipant>();

Console.WriteLine(
    $"Shared equal: {Convert.ToHexString(clientParticipant.SharedSecret) == Convert.ToHexString(serverParticipant.SharedSecret)}," +
    $"Shared secret: {Convert.ToHexString(clientParticipant.SharedSecret)}");