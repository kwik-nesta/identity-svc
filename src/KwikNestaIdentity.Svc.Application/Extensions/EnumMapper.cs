namespace KwikNestaIdentity.Svc.Application.Extensions
{
    public static class EnumMapper
    {
        public static TTarget Map<TSource, TTarget>(TSource source)
            where TSource : struct, Enum
            where TTarget : struct, Enum
        {
            // Try parse by name first
            if (Enum.TryParse<TTarget>(source.ToString(), out var target))
            {
                return target;
            }

            // Fallback by numeric value
            var underlying = Convert.ToInt32(source);
            if (Enum.IsDefined(typeof(TTarget), underlying))
            {
                return (TTarget)Enum.ToObject(typeof(TTarget), underlying);
            }

            throw new ArgumentException(
                $"Cannot map {typeof(TSource).Name}.{source} to {typeof(TTarget).Name}");
        }
    }
}
