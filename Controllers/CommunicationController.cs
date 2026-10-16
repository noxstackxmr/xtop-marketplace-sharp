using System.Text.Json;
using MarketplaceCore.Crypto;
using MarketplaceCore.Models;
using MarketplaceCore.Options;
using MarketplaceCore.Services.Channels;
using MarketplaceCore.Services.Indexer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace MarketplaceCore.Controllers;

[ApiController]
[Route("api/communication")]
[EnableRateLimiting("http")]
[ResponseCache(NoStore = true, Location = ResponseCacheLocation.None)]
public sealed class CommunicationController(IListingDirectory listings, RelayState state,
    IOptions<MarketplaceOptions> marketplace, IOptions<ChannelOptions> channels, TimeProvider clock, RelayAdmission admission) : ControllerBase
{
    [HttpGet]
    public IActionResult Get() => Ok(new
    {
        protocolVersion = 1,
        serverTime = clock.GetUtcNow().ToUnixTimeSeconds(),
        network = marketplace.Value.Network,
        networkId = marketplace.Value.NetworkId,
        marketplaceId = marketplace.Value.Id,
        origin = marketplace.Value.PublicOrigin,
        hubPath = "/hubs/communication",
        mode = "client",
        cipherSuite = "P256-HKDF-SHA256-AES256GCM",
        heartbeatIntervalSeconds = 10,
        presenceTimeoutSeconds = channels.Value.PresenceTimeoutSeconds,
        acceptTimeoutSeconds = channels.Value.AcceptTimeoutSeconds,
        lifetimeMinutes = 5,
        admissionRequired = true,
        maximumMessageBytes = channels.Value.MaximumMessageBytes,
        maximumMessages = channels.Value.MaximumMessages
    });

    [HttpPost("admission")]
    [EnableRateLimiting("admission")]
    [RequestSizeLimit(4096)]
    public async Task<IActionResult> Admit(AdmissionRequest request, CancellationToken token)
    {
        try { return Ok(await admission.Issue(request, token)); }
        catch (RelayException e) { return StatusCode(403, new { error = e.Message }); }
        catch (FormatException) { return BadRequest(new { error = "invalid_admission" }); }
        catch (Exception e) when (DirectoryFailure(e)) { return StatusCode(503, new { error = "indexer_unavailable" }); }
    }

    [HttpGet("sellers/{ownerKey}/eligibility")]
    public async Task<IActionResult> Eligibility(string ownerKey, CancellationToken token)
    {
        if (!OwnerSignature.IsOwner(ownerKey)) return BadRequest(new { error = "invalid_owner_key" });
        try { return Ok(new { ownerKey, eligible = await listings.SellerAsync(ownerKey, token) != null }); }
        catch (Exception e) when (DirectoryFailure(e)) { return StatusCode(503, new { error = "indexer_unavailable" }); }
    }

    private static bool DirectoryFailure(Exception e) => e is HttpRequestException or InvalidDataException or JsonException or TaskCanceledException ||
        e is InvalidOperationException { Message: "indexer state unavailable" };

    [HttpGet("listings/{listingId}/availability")]
    public async Task<ActionResult<Availability>> Availability(string listingId, CancellationToken cancellationToken)
    {
        try { OwnerSignature.Hex(listingId, 32); }
        catch (FormatException) { return BadRequest(new { error = "invalid_listing_id" }); }
        try
        {
            var listing = await listings.GetAsync(listingId, cancellationToken);
            var reason = state.ListingUnavailable(listing);
            var online = listing != null && state.IsOnline(listing.SellerOwnerKey);
            return Ok(new Availability(listingId, listing?.SellerOwnerKey, online,
                reason == null && online, reason ?? (online ? null : "seller_offline")));
        }
        catch (Exception exception) when (exception is HttpRequestException or InvalidDataException or JsonException or
            FormatException or TaskCanceledException || exception is InvalidOperationException { Message: "indexer state unavailable" })
        {
            Response.Headers.RetryAfter = "2";
            return StatusCode(503, new { error = "indexer_unavailable" });
        }
    }
}
