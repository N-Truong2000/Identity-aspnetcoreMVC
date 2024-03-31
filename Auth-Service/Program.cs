using Auth_Service.Data;
using Auth_Service.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddCors();

builder.Services.AddDbContext<ApplicationDBContext>(option =>
{
    var connString = builder.Configuration.GetConnectionString("Default");
    option.UseSqlServer(connString);
});
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDBContext>()
    .AddDefaultTokenProviders()
    .AddSignInManager();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();

app.MapPost(pattern: "/authen", handler: async ([FromBody]AuthenModel model, SignInManager<IdentityUser> _signInManager) =>
{
    var signinResult = await _signInManager.PasswordSignInAsync(model.UserName, model.Password, isPersistent: true, lockoutOnFailure: true);
    if (signinResult.Succeeded)
    {
        var jwt = GenerateJwt(model.UserName);
        var response = new { access_token = jwt };
        return Results.Ok(response);

    }
    string GenerateJwt(string userName)
    {
        var keyString = app.Configuration["EncryptionKey"] ?? "";
        var keyBytes = Encoding.ASCII.GetBytes(keyString);
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Subject = new ClaimsIdentity(new[] { new Claim(type: ClaimTypes.Name, value: userName) }),
            Expires = DateTime.UtcNow.AddDays(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(keyBytes), algorithm: SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
    throw new Exception("signin was not success!");
});
app.MapGet(pattern: "/validate", handler: async ( string token) =>
{
    var keyString = app.Configuration["EncryptionKey"] ?? "";
    var keyBytes = Encoding.ASCII.GetBytes(keyString);

    var tpkenHandler = new JwtSecurityTokenHandler();
    var validationParamerters = new TokenValidationParameters()
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateIssuer = false,
        ValidateAudience = false,
        RequireExpirationTime = true,
        ValidateLifetime = true,
    };
    var principal = await tpkenHandler.ValidateTokenAsync(token, validationParamerters);
    return principal.Claims;
});


app.Run();


