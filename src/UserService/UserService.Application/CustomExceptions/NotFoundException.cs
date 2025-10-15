using System;

namespace UserService.Application.CustomExceptions
{
    public class NotFoundException : Exception
    {
        public NotFoundException() 
            : base("User not found exception") 
        { }

        public NotFoundException(string message) : base(message) { }

        public NotFoundException(string message, Exception inner) 
            : base(message, inner) 
        { }
    }
}
