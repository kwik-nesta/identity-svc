using FluentValidation;
using KwikNestaIdentity.Svc.Application.Commands.UpdateBasicDetails;

namespace KwikNestaIdentity.Svc.Application.Validations
{
    internal class UserBasicDetailsRequestValidator : AbstractValidator<UpdateBasicUserDetailsCommand>
    {
        public UserBasicDetailsRequestValidator()
        {
            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("First Name field is required.");
            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("Last Name field is required.");
            RuleFor(x => x.Gender)
                .IsInEnum().WithMessage("Invalid Gender");
        }
    }
}