namespace KwikNestaIdentity.Svc.Contract.Responses
{
    public static class ResponseMessages
    {
        public static readonly string AccountCreated = "Account successfully created. Please use the OTP sent to your email to complete the process.";
        public static readonly string AccountDeactivated = "Account successfully deactivated. You can still request reactivation within the next 90 days.";
        public static readonly string AccountReactivationRequested = "Account reactivation request successful. Please enter the OTP sent to your email to complete the process";
        public static readonly string AccountReactivated = "Account successfully reactivated. Please proceed to login";
        public static readonly string OTPExpired = "OTP has expired. Please request for a new one.";
        public static readonly string InvalidOTP = "Invalid OTP. Please check and try again.";
        public static readonly string UserNotFoundWithEmail = "No user found with the specified email address";
        public static readonly string InvalidRequest = "Invalid request. Please check your inputs and try again";
        public static readonly string UserNotFoundWithId = $"No user record found with the given Id";
    }
}
