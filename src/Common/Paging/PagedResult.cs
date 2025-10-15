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

        // Factory method CŨ: Dùng cho Memory Paging (không nên dùng với DB Paging)
        // public static PagedResult<T> Create(IEnumerable<T> source, int page, int perPage) { ... }


        // **Factory method MỚI: Dùng cho Database Paging (Phân trang hiệu quả)**
        public static PagedResult<T> Create(List<T> items, int page, int perPage, int totalCount)
        {
            if (page <= 0) page = 1;
            if (perPage <= 0) perPage = 10;
            if (totalCount < 0) totalCount = 0;

            var hasMore = page * perPage < totalCount;

            return new PagedResult<T>
            {
                // Items đã được Skip() và Take() trên database, nên chỉ cần gán vào
                Items = items ?? new List<T>(),
                Page = page,
                PerPage = perPage,
                TotalCount = totalCount,
                HasMore = hasMore
            };
        }
    }
}