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
public sealed class CustodyController(CustodySessions sessions, CustodyKeys keys, IOptions<MarketplaceOptions> marketplace, TimeProvider clock) : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new { protocolVersion = 1, serverTime = clock.GetUtcNow().ToUnixTimeSeconds(), enabled = keys.Enabled, network = marketplace.Value.Network,
        networkId = marketplace.Value.NetworkId, marketplaceId = marketplace.Value.Id, origin = marketplace.Value.PublicOrigin,
        mode = "marketplace", automaticSubmission = true, ownerKey = keys.Enabled ? Convert.ToHexStringLower(keys.Owner) : null,
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
        catch (CustodyCapacityException)
        { Response.Headers.RetryAfter = "2"; return StatusCode(429, new { error = "custody_busy" }); }
        catch (Exception e) when (e is FormatException or CryptographicException or JsonException or OverflowException or ArgumentException or KeyNotFoundException)
        { return BadRequest(new { error = "invalid_custody_request" }); }
        catch (InvalidOperationException e) when (e.Message == "custody_busy")
        { Response.Headers.RetryAfter = "2"; return StatusCode(429, new { error = "custody_busy" }); }
        catch (InvalidOperationException e) when (e.Message is "indexer_syncing" or "node_or_indexer_not_ready")
        { Response.Headers.RetryAfter = "2"; return StatusCode(503, new { error = "custody_syncing" }); }
        catch (InvalidOperationException e)
        { return Conflict(new { error = e.Message is "item_busy" or "custody_session_expired" or "custody_request_expired" ? e.Message : "custody_unavailable" }); }
        catch (Exception e) when (e is HttpRequestException or InvalidDataException or IOException or TaskCanceledException)
        { return StatusCode(503, new { error = "custody_dependency_unavailable" }); }
    }
}
