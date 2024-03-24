using AspnetIdentityV2.Models;
using AspnetIdentityV2.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Client;
using System.Security.Claims;

namespace AspnetIdentityV2.Controllers
{

    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _emailSender;
        public IdentityController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IEmailSender emailSender)
        {
            _roleManager = roleManager;
            _signInManager = signInManager;
            _userManager = userManager;
            _emailSender = emailSender;
        }
        public IActionResult SignUp()

        {
            var model = new SignupViewModel() { Role = "Member" };
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> SignUp(SignupViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (!(await _roleManager.RoleExistsAsync(model.Role)))
                {
                    var role = new IdentityRole()
                    {
                        Name = model.Role,
                    };
                    var roleResult = await _roleManager.CreateAsync(role);
                    if (!roleResult.Succeeded)
                    {
                        var error = roleResult.Errors.Select(x => x.Description);
                        ModelState.AddModelError("Role", string.Join(" ", error));
                        return View(model);
                    }
                }
                if (await _userManager.FindByEmailAsync(model.Email) == null)
                {
                    var user = new IdentityUser
                    {
                        Email = model.Email,
                        UserName = model.Email
                    };

                    var result = await _userManager.CreateAsync(user, model.Password);

                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    if (result.Succeeded)
                    {
                        var claim = new Claim("Dapartment", model.Department);
                        await _userManager.AddClaimAsync(user, claim);

                        await _userManager.AddToRoleAsync(user, model.Role);

                        var configrationLink = Url.ActionLink("ConfirmEmail", "Identity", new { userId = user.Id, @token = token });
                        await _emailSender.SendEmailAsync("tranhuunhattruong9a4@gmail.com", model.Email, "Confire your email address", configrationLink);

                        return RedirectToAction("SignIn");
                    }

                    ModelState.AddModelError("SignUp", string.Join("", result.Errors.Select(x => x.Description)));
                    return View(model);
                }
                else
                {
                    ModelState.AddModelError("SignUp", "Email is already taken.");
                    return View(model);
                }
            }
            return View(model);
        }
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (result.Succeeded)
            {
                return RedirectToAction("SignIn");

            }
            return new NoContentResult();
        }
        public IActionResult SignIn()
        {
            return View(new SigninViewModel());
        }
        [HttpPost]
        public async Task<IActionResult> SignIn(SigninViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe, true);
                if (result.IsLockedOut)
                {
                    ModelState.AddModelError("SignIn", "Lockout.");
                    return View(model);

                }
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByEmailAsync(model.Username);
                    var userClaim = await _userManager.GetClaimsAsync(user);
                    if (!userClaim.Any(x => x.Type == "Dapartment"))
                    {
                        ModelState.AddModelError("SignIn", "User not in tech department");
                        return View(model);
                    }
                    if (await _userManager.IsInRoleAsync(user, "Member"))
                    {
                        return RedirectToAction("Member", "Home");
                    }
                }
                else
                {
                    ModelState.AddModelError("SignIn", "Cannot login.");
                    return View(model);
                }
            }
            else
            {
                return View(model);
            }
            return View(model);
        }
        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }
        public async Task<IActionResult> SignOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Signin");
        }

        [Authorize]
        public async Task<IActionResult> MFASetup()
        {
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var model = new MFAViewModel() { Token = token };
            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MFASetup(MFAViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var reuslt = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);
                if (reuslt)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("MFA", "Your MFA code could not be validated.");
                    return View(model);
                }
            }

            return View(model);
        }
    }
}
