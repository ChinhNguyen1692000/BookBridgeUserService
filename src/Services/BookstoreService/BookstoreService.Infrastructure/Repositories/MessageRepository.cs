using BookstoreService.Domain.Entities;
using BookstoreService.Infrastructure.DBContext;
using BookstoreService.Infrastructure.Repositories;
using Common.Infrastructure.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookstoreService.Infracstructure.Repositories
{
    public class MessageRepository : BaseRepository<Message, long>
    {
        public MessageRepository(BookstoreDBContext context) : base(context) { }
    }
}
