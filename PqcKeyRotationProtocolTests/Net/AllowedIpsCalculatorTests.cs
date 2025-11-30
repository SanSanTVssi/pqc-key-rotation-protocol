using PqcKeyRotationProtocol.Net;

namespace PqcKeyRotationProtocolTests.Net;

public class AllowedIpsCalculatorTests
{
    private readonly AllowedIpsCalculator m_calc = new();

    [Fact]
    public void Calculate_ReturnsAllowedIfNoDisallowed()
    {
        var result = m_calc.Calculate("10.0.0.0/24", "");

        Assert.Equal("AllowedIPs = 10.0.0.0/24", result);
    }

    [Fact]
    public void Calculate_RemovesExactDisallowedSubnet()
    {
        var result = m_calc.Calculate("10.0.0.0/24", "10.0.0.0/24");

        Assert.Equal("There are no allowed networks!", result);
    }

    [Fact]
    public void Calculate_RemovesPartOfSubnet()
    {
        var result = m_calc.Calculate("10.0.0.0/24", "10.0.0.0/25");

        // 10.0.0.128–10.0.0.255 → 10.0.0.128/25
        Assert.Equal("AllowedIPs = 10.0.0.128/25", result);
    }

    [Fact]
    public void Calculate_RemovesMiddleChunk()
    {
        var result = m_calc.Calculate("10.0.0.0/24", "10.0.0.64/26");

        // Allowed ranges:
        // 10.0.0.0–63 → 10.0.0.0/26
        // 10.0.0.128–255 → 10.0.0.128/25
        Assert.Equal("AllowedIPs = 10.0.0.0/26,10.0.0.128/25", result);
    }

    [Fact]
    public void Calculate_MultipleAllowedAndDisallowed()
    {
        var allowed = "10.0.0.0/25,10.0.0.128/25";
        var disallowed = "10.0.0.64/26,10.0.0.192/26";

        var result = m_calc.Calculate(allowed, disallowed);

        Assert.Equal("AllowedIPs = 10.0.0.0/26,10.0.0.128/26", result);
    }

    [Fact]
    public void Calculate_ShiftsZeroStartTo_1_0_0_0()
    {
        var result = m_calc.Calculate("0.0.0.0/1", "");

        Assert.StartsWith("AllowedIPs = 1.0.0.0/", result);
    }

    [Fact]
    public void Calculate_NoAllowedNetworks_ReturnsError()
    {
        var result = m_calc.Calculate("", "10.0.0.0/24");

        Assert.Equal("There are no allowed networks!", result);
    }
}