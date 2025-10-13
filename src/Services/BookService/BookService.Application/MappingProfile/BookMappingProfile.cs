using AutoMapper;
using BookService.Application.Models;
using BookService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookService.Application.MappingProfile
{
    public class BookMappingProfile : Profile
    {
        public BookMappingProfile()
        {
            CreateMap<BookCreateRequest, Book>();
            CreateMap<BookUpdateReuest, Book>()
    .ForMember(b => b.IsActive, ac => ac.Ignore())
    .ForMember(b => b.RatingsCount, ac => ac.Ignore())
    .ForMember(b => b.AverageRating, ac => ac.Ignore());

        }
    }
}
