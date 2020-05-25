using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;


// For more information on enabling MVC for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace WebAdvert.Web.Controllers
{
    public class Accounts : Controller
    {
        // GET: /<controller>/
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;

        public Accounts(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> usermanager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = usermanager;
            _pool = pool;
        }
        public async Task<IActionResult> Signup()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _pool.GetUser(model.Email);
                if (user.Status != null)
                {
                    ModelState.AddModelError("User Exists", "User with this e-mail already exists");
                    return View(model);
                }
                user.Attributes.Add("name", model.Email);
                var createdUser = await _userManager.CreateAsync(user, model.Password);
                if (createdUser.Succeeded)
                {
                    return RedirectToAction("Confirm");
                }
            }
            return View(model);
        }

        public async Task<IActionResult> Confirm()
        {
            var model = new ConfirmModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = _userManager.FindByEmailAsync(model.Email).Result;
                if (user.Status == null)
                {
                    ModelState.AddModelError("NotFound", "A user with the given email address was not found.");
                    return View(model);
                }
                var result = await (_userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, false).ConfigureAwait(false);
                if (result.Succeeded)
                {
                    return RedirectToAction("index", "home");
                }
                else
                {
                    foreach (var err in result.Errors)
                    {
                        ModelState.AddModelError(err.Code, err.Description);
                    }
                    return View(model);
                }
            }
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Signin(SigninModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("Signin")]
        public async Task<IActionResult> SigninPost(SigninModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false).ConfigureAwait(false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and Password did not match.");
                }
            }
            return View("Signin", model);
        }

    }
}
