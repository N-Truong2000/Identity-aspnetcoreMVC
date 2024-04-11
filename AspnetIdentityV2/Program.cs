using AspnetIdentityV2.Data;
using AspnetIdentityV2.Models;
using AspnetIdentityV2.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);
// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddDbContext<ApplicationDBContext>(options =>
{
    var connString = builder.Configuration.GetConnectionString("Default");
    options.UseSqlServer(connString);
});

builder.Services.AddIdentity<IdentityUser, IdentityRole>().AddEntityFrameworkStores<ApplicationDBContext>().AddDefaultTokenProviders();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(1);

    options.SignIn.RequireConfirmedEmail = true;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Identity/SignIn";
    options.AccessDeniedPath = "/Identity/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(10);
});

builder.Services.AddAuthentication().AddFacebook(option =>
{
    option.AppId = builder.Configuration["FacebookAppId"];
    option.AppSecret = builder.Configuration["FacebookAppSecret"];
});

//builder.Services.Configure<SmtpOptions>(builder.Configuration["Smtp"]);
#region   DI
builder.Services.AddScoped<IEmailSender, SmtpEmailSender>();
#endregion
builder.Services.AddAuthorization(option =>
{
    option.AddPolicy("MemberDep", p =>
    {
        p.RequireClaim("Dapartment", "tech").RequireRole("Member");
    });
    option.AddPolicy("AdminDep", p =>
    {
        p.RequireClaim("Dapartment", "IT").RequireRole("Admin");
    });
});


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
