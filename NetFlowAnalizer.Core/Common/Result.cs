namespace NetFlowAnalizer.Core;

public readonly struct Result<T>
{
    private readonly T? _value;
    private readonly string _error;
   
    public bool IsSuccess { get; }

    public bool IsFailure { get; }

    public T? Value => IsSuccess ? _value : throw new InvalidOperationException($"Cannot access Value when Result is failure. Error: {_error}");
    public string Error => IsFailure ? _error: throw new InvalidOperationException($"Cannot access Error when Result is success");

    public static Result<T> Success(T? value) => new Result<T>(value, true, string.Empty);

    public static Result<T> Failure(string error) => new (default, false, error);
    public Result(T? value, bool isSuccess, string error)
    {
        _value = value;
        _error = error;
        IsSuccess = isSuccess;
    }
}
