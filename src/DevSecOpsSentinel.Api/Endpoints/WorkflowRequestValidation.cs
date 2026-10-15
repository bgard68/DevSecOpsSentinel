using Microsoft.AspNetCore.Mvc;

namespace DevSecOpsSentinel.Api.Endpoints;

/// <summary>
/// The problem responses every workflow endpoint can return, in one place.
///
/// Each handler used to carry its own copy of the request checks and its own copy of the
/// 422 mapping. Four copies of a size limit is four chances for the fifth endpoint to be
/// written without one, and the duplicated prose meant two endpoints could describe the same
/// failure differently.
/// </summary>
internal static class WorkflowRequestValidation
{
    /// <summary>
    /// A missing body and a blank one are the same failure to a caller: the request did not
    /// carry a workflow.
    /// </summary>
    public static IResult MissingOrInvalidRequest() =>
        Results.BadRequest(new ProblemDetails
        {
            Title = "Invalid workflow request",
            Detail = "Both fileName and content are required.",
            Status = StatusCodes.Status400BadRequest
        });

    public static IResult TooLarge(int maximumCharacters) =>
        Results.Problem(
            title: "Workflow is too large",
            detail: $"Workflow content cannot exceed {maximumCharacters:N0} characters.",
            statusCode: StatusCodes.Status413PayloadTooLarge);

    /// <summary>
    /// A document the YAML parser rejected is reported rather than partially analysed — see
    /// ADR-001. Shared so every endpoint describes it identically.
    /// </summary>
    public static IResult InvalidWorkflowYaml(IEnumerable<string> validationErrors) =>
        Results.Problem(
            title: "Workflow YAML could not be parsed",
            detail: string.Join(" ", validationErrors),
            statusCode: StatusCodes.Status422UnprocessableEntity);

    /// <summary>
    /// The one definition of a serviceable workflow request. Returns null when there is
    /// nothing to report.
    /// </summary>
    public static IResult? Validate(IWorkflowRequest? request, int maximumCharacters)
    {
        if (request is null ||
            string.IsNullOrWhiteSpace(request.FileName) ||
            string.IsNullOrWhiteSpace(request.Content))
        {
            return MissingOrInvalidRequest();
        }

        return request.Content.Length > maximumCharacters
            ? TooLarge(maximumCharacters)
            : null;
    }
}

/// <summary>
/// Applies <see cref="WorkflowRequestValidation.Validate"/> to every request reaching the
/// workflow endpoints, so a handler runs only once its input is known to be serviceable.
///
/// Attached to the route group rather than to each endpoint: a new workflow endpoint is
/// covered by being in the group, which is the property the four hand-written copies of
/// these checks did not have.
///
/// Every endpoint in the group takes an <see cref="IWorkflowRequest"/> body — that is what
/// the group is. One that does not would be rejected here as though its body were missing,
/// which is a loud failure in that endpoint's own first test rather than a quiet one in
/// production.
/// </summary>
internal sealed class WorkflowRequestValidationFilter(int maximumCharacters) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        // A null body is not in Arguments as an IWorkflowRequest, so it arrives here as
        // null and is reported as the missing request it is.
        IResult? failure = WorkflowRequestValidation.Validate(
            context.Arguments.OfType<IWorkflowRequest>().FirstOrDefault(),
            maximumCharacters);

        return failure is not null
            ? failure
            : await next(context);
    }
}
