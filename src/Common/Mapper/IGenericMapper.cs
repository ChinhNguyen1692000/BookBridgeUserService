using System.Collections.Generic;

namespace Common.Mapper
{
    public interface IGenericMapper
    {
        TDestination Map<TSource, TDestination>(TSource source);
        IEnumerable<TDestination> MapList<TSource, TDestination>(IEnumerable<TSource> source);
    }
}
