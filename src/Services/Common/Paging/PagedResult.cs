using System;
using System.Collections.Generic;
using System.Linq;

namespace Common.Paging
{
    public class PagedResult<T>
    {
        public List<T> Items { get; private set; } = new List<T>();
        public int Page { get; private set; }
        public int PerPage { get; private set; }
        public int TotalCount { get; private set; }
        public bool HasMore { get; private set; }

        private PagedResult() { }

        // Factory method
        public static PagedResult<T> Create(IEnumerable<T> source, int page, int perPage)
        {
            if (page <= 0) page = 1;
            if (perPage <= 0) perPage = 10;

            var totalCount = source is ICollection<T> collection
                ? collection.Count
                : new List<T>(source).Count;

            var skip = (page - 1) * perPage;
            var items = new List<T>(source).GetRange(
                skip, Math.Min(perPage, Math.Max(0, totalCount - skip))
            );

            var hasMore = page * perPage < totalCount;

            return new PagedResult<T>
            {
                Items = items,
                Page = page,
                PerPage = perPage,
                TotalCount = totalCount,
                HasMore = hasMore
            };
        }
    }
}
