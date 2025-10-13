using System;

namespace UserService.Application.CustomExceptions
{
    public class AccountNotActiveException : Exception
    {
        public AccountNotActiveException() 
            : base("Account is not active. An activation OTP has been sent to your email.") 
        { }

        public AccountNotActiveException(string message) : base(message) { }

        public AccountNotActiveException(string message, Exception inner) 
            : base(message, inner) 
        { }
    }
}
