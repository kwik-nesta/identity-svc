using FluentValidation;
using KwikNestaIdentity.Svc.Contract.Protos;

namespace KwikNestaIdentity.Svc.Application.Validations
{
    public class RegistrationValidator : AbstractValidator<RegisterRequest>
    {
        public RegistrationValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("{PropertyName} field is required.")
                .EmailAddress().WithMessage("Please enter a valid email address.");
            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("{PropertyName} field is required.");
            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("{PropertyName} field is required.");
            RuleFor(x => x.PhoneNumber)
                .NotEmpty().WithMessage("{PropertyName} field is required.");
            RuleFor(x => x.Password)
                .NotEmpty().WithMessage("{PropertyName} field is required.")
                .MinimumLength(8).WithMessage("{PropertyName} field must be at least 8 characters.");
            RuleFor(x => x.ConfirmPassword)
                .NotEmpty().WithMessage("{PropertyName} field is required.")
                .MinimumLength(8).WithMessage("{PropertyName} field must be at least 8 characters.");
            RuleFor(x => x)
                .Must(args => ValidationExtensions.IsAMatch(args.Password, args.ConfirmPassword))
                .WithMessage("NewPassword and Confirm NewPassword must match");
            RuleFor(x => x.SystemRole)
                .IsInEnum().WithMessage("Invalid role type");
            RuleFor(x => x).Must(args => ValidationExtensions.IsAValidRole(args.SystemRole))
                .WithMessage("Please select a valid role");
            RuleFor(x => x.Gender)
                .IsInEnum().WithMessage("Invalid Gender");
        }
    }
}
