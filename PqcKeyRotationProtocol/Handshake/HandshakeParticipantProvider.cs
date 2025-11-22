// using PqcKeyRotationProtocol.Config;
//
// namespace PqcKeyRotationProtocol.Handshake;
//
// public class HandshakeParticipantProvider(IProvider<AppConfig> appConfigProvider) : IProvider<IHandshakeParticipant>
// {
//     private readonly AppConfig _appConfig = appConfigProvider.Provide();
//     public IHandshakeParticipant Provide()
//     {
//         switch (_appConfig.Mode)
//         {
//             case ApplicationMode.Client:
//                 Container.RegisterSingleton<IHandshakeParticipant, PqcClient>();
//                 break;
//             case ApplicationMode.Server:
//                 Container.RegisterSingleton<IHandshakeParticipant, PqcServer>();
//                 break;
//             default:
//                 throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
//         }
//     }
// }