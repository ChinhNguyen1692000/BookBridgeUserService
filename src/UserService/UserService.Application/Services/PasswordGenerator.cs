using System;
using System.Security.Cryptography;
using System.Text;

public class PasswordGenerator : IPasswordGenerator
{
    private const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    private const string Digits = "0123456789";
    private const string SpecialChars = "!@#$%^&*()-_=+[]{};:,.<>?";

    private static readonly char[] AllChars = (Uppercase + Lowercase + Digits + SpecialChars).ToCharArray();

    public string GenerateRandomPassword(int length = 12)
    {
        if (length < 8)
            throw new ArgumentException("Password length should be at least 8 characters.");

        var password = new char[length];
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[length];

        rng.GetBytes(bytes);

        for (int i = 0; i < length; i++)
        {
            // Chọn ký tự random từ AllChars
            password[i] = AllChars[bytes[i] % AllChars.Length];
        }

        // Đảm bảo ít nhất 1 ký tự upper, lower, digit, special
        password[0] = Uppercase[bytes[0] % Uppercase.Length];
        password[1] = Lowercase[bytes[1] % Lowercase.Length];
        password[2] = Digits[bytes[2] % Digits.Length];
        password[3] = SpecialChars[bytes[3] % SpecialChars.Length];

        // Xáo trộn mảng password
        return Shuffle(password);
    }

    private string Shuffle(char[] array)
    {
        var rng = RandomNumberGenerator.Create();
        int n = array.Length;
        while (n > 1)
        {
            var box = new byte[1];
            rng.GetBytes(box);
            int k = box[0] % n;
            n--;
            (array[n], array[k]) = (array[k], array[n]);
        }
        return new string(array);
    }
}
