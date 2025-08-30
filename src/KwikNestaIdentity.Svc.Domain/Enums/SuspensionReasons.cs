using System.ComponentModel;

namespace KwikNestaIdentity.Svc.Domain.Enums
{
    public enum SuspensionReasons
    {
        [Description("Account suspended due to unusual or suspicious login activity.")]
        SuspiciousActivity,
        [Description("Account suspended because it may have been compromised.")]
        CompromisedAccount,
        [Description("Account suspended for violating terms of service or community guidelines.")]
        PolicyViolation,
        [Description("Account suspended for fraudulent or malicious behavior.")]
        FraudulentBehavior,
        [Description("Account suspended due to repeated failed payments.")]
        PaymentFailure,
        [Description("Account temporarily suspended pending investigation.")]
        PendingInvestigation,
        [Description("Account suspended due to duplicate or multiple accounts violation.")]
        DuplicateAccount,
        [Description("Account suspended after multiple user reports.")]
        UserReports,
        [Description("Account suspended for abusing system resources or spamming.")]
        SystemAbuse,
        [Description("Account suspended for other administrative reasons.")]
        Other
    }
}
