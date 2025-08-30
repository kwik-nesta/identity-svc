using FluentValidation;
using KwikNestaIdentity.Svc.Contract.Requests;

namespace KwikNestaIdentity.Svc.Application.Validations
{
    public class LoginValidator : AbstractValidator<LoginRequest>
    {
        public LoginValidator()
        {
            RuleFor(x => x.UserName)
                .NotEmpty().WithMessage("User Name field is required.")
                .EmailAddress().WithMessage("Please enter a valid email address.");
            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("{PropertyName} field is required.")
                .MinimumLength(8).WithMessage("{PropertyName} field must be at least 8 characters.");
        }
    }
}