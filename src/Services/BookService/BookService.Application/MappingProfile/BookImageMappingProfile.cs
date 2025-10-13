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
    public class BookImageMappingProfile : Profile
    {
        public BookImageMappingProfile()
        {
            CreateMap<BookImageCreateRequest, BookImage>();
            CreateMap<BookImageUpdateRequest, BookImage>();

        }
    }
}
