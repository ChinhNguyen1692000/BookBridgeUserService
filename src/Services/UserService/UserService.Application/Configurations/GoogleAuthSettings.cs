namespace UserService.Application.Configurations
{
    public class GoogleAuthSettings
    {
        public string ClientIdWeb { get; set; } = string.Empty;
        public string ClientIdAndroid { get; set; } = string.Empty;
        public List<string> AcceptedAudiences { get; set; } = new List<string>();
    }
}
