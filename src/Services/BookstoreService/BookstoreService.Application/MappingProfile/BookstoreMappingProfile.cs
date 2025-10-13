using AutoMapper;
using BookstoreService.Application.Models;
using BookstoreService.Domain.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BookstoreService.Application.MappingProfile
{
    public class BookstoreMappingProfile : Profile
    {
        public BookstoreMappingProfile()
        {
            CreateMap<BookstoreCreateRequest, Bookstore>();
            CreateMap<BookstoreUpdateRequest, Bookstore>()
                .ForMember(dest => dest.CreatedDate, opt => opt.Ignore())
                .ForMember(dest => dest.IsActive, opt => opt.Ignore());
        }
    }
}
