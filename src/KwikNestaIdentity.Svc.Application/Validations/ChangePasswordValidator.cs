using FluentValidation;
using KwikNestaIdentity.Svc.Contract.Protos;

namespace KwikNestaIdentity.Svc.Application.Validations
{
    public class ChangePasswordValidator : AbstractValidator<ChangePasswordRequest>
    {
        public ChangePasswordValidator()
        {
            RuleFor(x => x.CurrentPassword)
                .NotEmpty().WithMessage("User Name field is required.")
                .EmailAddress().WithMessage("Please enter a valid email address.");
            RuleFor(x => x.NewPassword)
               .NotEmpty().WithMessage("New Password field is required.")
               .MinimumLength(8).WithMessage("New Password field must be at least 8 characters.");
            RuleFor(x => x)
                .Must(args => ValidationExtensions.IsAMatch(args.NewPassword, args.ConfirmNewPassword))
                .WithMessage("New Password and Confirm New Password must match");
        }
    }
}