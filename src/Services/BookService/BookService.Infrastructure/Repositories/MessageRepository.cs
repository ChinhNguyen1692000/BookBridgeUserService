using BookService.Domain.Entities;
using BookService.Infracstructure.DBContext;
using Common.Infrastructure.Repositories;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Infracstructure.Repositories
{
    public class MessageRepository : BaseRepository<Message, long>
    {
        public MessageRepository(BookDBContext context) : base(context) { }

    }
}
