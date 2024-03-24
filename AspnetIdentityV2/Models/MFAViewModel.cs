using System.ComponentModel.DataAnnotations;

namespace AspnetIdentityV2.Models
{
    public class MFAViewModel
    {
        [Required]
        public string Token { get; set; }
        public string Code { get; set; }

    }
}
