namespace DevSecOpsSentinel.Domain;

/// <summary>
/// Severities the rule engine can assign. Every member is produced by at least
/// one rule; an unused level would appear in the client's ordering and in
/// exports as a category that can never be populated.
/// </summary>
public enum WorkflowSeverity
{
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}
