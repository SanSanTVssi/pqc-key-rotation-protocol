using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace PqcKeyRotationProtocol.Net;

public interface IAllowedIpsCalculator
{
    string Calculate(string allowed, string disallowed);
}

public readonly struct IPv4Network : IComparable<IPv4Network>
{
    public readonly uint Network;
    public readonly int Prefix;

    public IPv4Network(string cidr)
    {
        var parts = cidr.Split('/');
        if (parts.Length != 2)
        {
            throw new FormatException($"Invalid CIDR: {cidr}");
        }

        Prefix = int.Parse(parts[1]);
        Network = IpToUInt(parts[0]) & MaskToUInt(Prefix);
    }

    public IPv4Network(uint addr, int prefix)
    {
        Prefix = prefix;
        Network = addr & MaskToUInt(prefix);
    }

    public uint First => Network;
    public uint Last => Network | ~MaskToUInt(Prefix);

    public override string ToString()
    {
        return $"{UIntToIp(Network)}/{Prefix}";
    }

    public int CompareTo(IPv4Network other)
    {
        return Network.CompareTo(other.Network);
    }

    public static uint MaskToUInt(int prefix)
    {
        return prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
    }

    public static uint IpToUInt(string ip)
    {
        var bytes = IPAddress.Parse(ip).GetAddressBytes();
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }
        return BitConverter.ToUInt32(bytes, 0);
    }

    public static string UIntToIp(uint ip)
    {
        var bytes = BitConverter.GetBytes(ip);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }
        return new IPAddress(bytes).ToString();
    }
}

public class AllowedIpsCalculator() : IAllowedIpsCalculator
{
    private readonly record struct IpRange(uint Start, uint End);

    public string Calculate(string allowed, string disallowed)
    {
        var allowedNets = allowed.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(a => new IPv4Network(a))
            .ToList();

        var disallowedNets = disallowed.Split(',', StringSplitOptions.RemoveEmptyEntries)
            .Select(a => new IPv4Network(a))
            .ToList();

        var allowedRanges = Summarize(allowedNets).ToList();
        var disallowedRanges = Summarize(disallowedNets).ToList();
        var resultRanges = SubtractRanges(allowedRanges, disallowedRanges).ToList();

        if (resultRanges.Count == 0)
        {
            return "There are no allowed networks!";
        }

        if (resultRanges[0].Start == IPv4Network.IpToUInt("0.0.0.0"))
        {
            resultRanges[0] = resultRanges[0] with { Start = IPv4Network.IpToUInt("1.0.0.0") };
        }

        var resultCidrs = ConvertRanges(resultRanges)
            .OrderBy(n => n.Network)
            .ToList();

        return $"AllowedIPs = {string.Join(",", resultCidrs.Select(n => n.ToString()))}";
    }

    private static IEnumerable<IpRange> Summarize(IEnumerable<IPv4Network> nets)
    {
        var ranges = nets
            .Select(n => new IpRange(n.First, n.Last))
            .OrderBy(r => r.Start)
            .ToList();

        var merged = new List<IpRange>();
        foreach (var r in ranges)
        {
            if (merged.Count == 0)
            {
                merged.Add(r);
                continue;
            }

            var lastIndex = merged.Count - 1;
            var last = merged[lastIndex];

            if (last.End + 1 >= r.Start)
            {
                merged[lastIndex] = new IpRange(last.Start, Math.Max(last.End, r.End));
            }
            else
            {
                merged.Add(r);
            }
        }

        return merged;
    }

    private static IEnumerable<IpRange> SubtractRanges(IEnumerable<IpRange> allowed, IEnumerable<IpRange> disallowed)
    {
        var result = allowed.ToList();

        foreach (var dis in disallowed)
        {
            var temp = new List<IpRange>();

            foreach (var a in result)
            {
                if (dis.End < a.Start || dis.Start > a.End)
                {
                    temp.Add(a);
                    continue;
                }

                if (dis.Start > a.Start)
                {
                    temp.Add(new IpRange(a.Start, dis.Start - 1));
                }

                if (dis.End < a.End)
                {
                    temp.Add(new IpRange(dis.End + 1, a.End));
                }
            }

            result = temp;
        }

        return result;
    }

    private static IEnumerable<IPv4Network> ConvertRanges(IEnumerable<IpRange> ranges)
    {
        foreach (var (start, end) in ranges)
        {
            var s = start;
            while (s <= end)
            {
                var prefix = 32;
                while (prefix > 0)
                {
                    var mask = IPv4Network.MaskToUInt(prefix - 1);
                    var net = s & mask;

                    if (net != s || (s | ~mask) > end)
                    {
                        break;
                    }

                    prefix--;
                }

                yield return new IPv4Network(s, prefix);
                s += (uint)(1 << (32 - prefix));

                if (s == 0)
                {
                    break;
                }
            }
        }
    }
}
