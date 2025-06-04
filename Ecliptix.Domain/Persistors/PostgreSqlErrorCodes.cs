namespace Ecliptix.Domain.Persistors;

public static class PostgreSqlErrorCodes
{
    public const string ConnectionException = "08000";
    public const string ConnectionDoesNotExist = "08003"; 
    public const string ConnectionFailure = "08006";
        
    public const string SerializationFailure = "40001";
        
    public const string UniqueViolation = "23505";
    public const string ForeignKeyViolation = "23503";
    public const string CheckViolation = "23514";
        
    public const string InvalidTextRepresentation = "22P02";
}