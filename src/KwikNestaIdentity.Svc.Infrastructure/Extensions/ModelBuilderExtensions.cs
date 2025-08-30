using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace KwikNestaIdentity.Svc.Infrastructure.Extensions
{
    public static class ModelBuilderExtensions
    {
        public static PropertyBuilder<List<string>> HasStringListConversion(
            this PropertyBuilder<List<string>> propertyBuilder, char separator = ',')
        {
            var comparer = new ValueComparer<List<string>>(
                (a, b) => a!.SequenceEqual(b!),
                a => a.Aggregate(0, (hash, value) => HashCode.Combine(hash, value.GetHashCode())),
                a => a.ToList()
            );

            propertyBuilder
                .HasConversion(
                    v => string.Join(separator, v ?? new List<string>()),
                    v => v.Split(separator, StringSplitOptions.RemoveEmptyEntries).ToList()
                )
                .Metadata.SetValueComparer(comparer);

            return propertyBuilder;
        }
    }
}