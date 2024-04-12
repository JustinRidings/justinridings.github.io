namespace PersonalSite.Data.Models
{
    public class ActivityResult
    {
        public string Activity { get; set; } = default!;
        public double Accessibility { get; set; }
        public string Type { get; set; } = default!;
        public int Participants { get; set; }
        public double Price { get; set; }
        public string? Link { get; set; }
    }
}
