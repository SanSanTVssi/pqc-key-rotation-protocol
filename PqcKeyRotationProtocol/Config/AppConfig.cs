using System.Net;

namespace PqcKeyRotationProtocol.Config;

public record AppConfig(ApplicationMode Mode , IPEndPoint ClientEp, IPEndPoint ServerEp);