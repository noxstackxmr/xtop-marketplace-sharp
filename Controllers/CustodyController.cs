using System.Security.Cryptography;
using System.Text.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Models;
using MarketplaceCore.Options;
using MarketplaceCore.Services.Custody;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Controllers;

[ApiController]
[Route("api/custody")]
[EnableRateLimiting("http")]
[RequestSizeLimit(400000)]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class CustodyController(CustodySessions sessions, CustodyKeys keys, IOptions<MarketplaceOptions> marketplace) : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new { protocolVersion = 1, enabled = keys.Enabled, network = marketplace.Value.Network,
        networkId = marketplace.Value.NetworkId, marketplaceId = marketplace.Value.Id, origin = marketplace.Value.PublicOrigin,
        mode = "marketplace", ownerKey = keys.Enabled ? Convert.ToHexStringLower(keys.Owner) : null,
        address = keys.Enabled ? CustodyAddress.From(keys.Address) : null, cipherSuite = "P256-HKDF-SHA256-AES256GCM" });

    [HttpPost("sessions")]
    public Task<IActionResult> Open(CustodyOpen request, CancellationToken cancellationToken)
        => Handle(async () => await sessions.OpenAsync(request, cancellationToken));

    [HttpPost("sessions/{id}/messages")]
    public Task<IActionResult> Exchange(string id, CustodyEnvelope message, CancellationToken cancellationToken)
        => Handle(async () => await sessions.ExchangeAsync(id, message, cancellationToken));

    private async Task<IActionResult> Handle(Func<Task<object>> action)
    {
        try { return Ok(await action()); }
        catch (Exception e) when (e is FormatException or CryptographicException or JsonException or OverflowException or ArgumentException or KeyNotFoundException)
        { return BadRequest(new { error = "invalid_custody_request" }); }
        catch (InvalidOperationException) { return Conflict(new { error = "custody_unavailable" }); }
        catch (Exception e) when (e is HttpRequestException or InvalidDataException or IOException or TaskCanceledException)
        { return StatusCode(503, new { error = "custody_dependency_unavailable" }); }
    }
}
