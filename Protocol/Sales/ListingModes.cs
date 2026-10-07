namespace MarketplaceCore.Protocol.Sales;

public static class ListingModes
{
    public const byte Marketplace = 1;
    public const byte Client = 2;

    public static bool IsListing(byte? operation) => operation is ListingProofs.ListOperation or ListingProofs.ClientListOperation;

    public static byte FromOperation(byte operation) => operation switch
    {
        ListingProofs.ListOperation => Marketplace,
        ListingProofs.ClientListOperation => Client,
        _ => throw new FormatException("invalid listing operation")
    };

    public static string Name(byte operation) => FromOperation(operation) == Client ? "client" : "marketplace";
}
