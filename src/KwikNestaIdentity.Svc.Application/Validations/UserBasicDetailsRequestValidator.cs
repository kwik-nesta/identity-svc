using FluentValidation;
using KwikNestaIdentity.Svc.Contract.Requests;

namespace KwikNestaIdentity.Svc.Application.Validations
{
    internal class UserBasicDetailsRequestValidator : AbstractValidator<UpdateUserBasicDetailsRequest>
    {
        public UserBasicDetailsRequestValidator()
        {
            RuleFor(x => x.FirstName)
                .NotEmpty().WithMessage("{PropertyName} field is required.");
            RuleFor(x => x.LastName)
                .NotEmpty().WithMessage("{PropertyName} field is required.");
            RuleFor(x => x.Gender)
                .IsInEnum().WithMessage("Invalid Gender");
        }
    }
}