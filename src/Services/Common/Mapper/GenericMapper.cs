using AutoMapper;
using Common.Mapper;
using System.Collections.Generic;

namespace Bookbridge.Common.Mapping
{
    public class GenericMapper : IGenericMapper
    {
        private readonly IMapper _mapper;

        public GenericMapper(IMapper mapper)
        {
            _mapper = mapper;
        }

        public TDestination Map<TSource, TDestination>(TSource source)
            => _mapper.Map<TDestination>(source);

        public IEnumerable<TDestination> MapList<TSource, TDestination>(IEnumerable<TSource> source)
            => _mapper.Map<IEnumerable<TDestination>>(source);
    }
}
