using Cross_Site_Scripting__XSS_.Models;
using Microsoft.AspNetCore.Mvc;

namespace Cross_Site_Scripting__XSS_.Controllers
{
    [Route("Student")]

    public class StudentController : Controller
    {
        [Route("~/")]
        public IActionResult Index()
        {
            return View();
        }
        [HttpPost]
        public IActionResult SignUp(StudentViewModel model)
        {
            return View("Result",model);
        }
    }
}
