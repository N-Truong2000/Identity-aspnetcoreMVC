namespace AspnetIdentityV2.Services
{
    public interface IEmailSender
    {

        Task SendEmailAsync(string to, string from, string subject, string message);
    }
}
