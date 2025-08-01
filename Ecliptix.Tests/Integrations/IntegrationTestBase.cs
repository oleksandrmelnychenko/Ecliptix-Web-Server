namespace Ecliptix.Tests.Integrations;

public abstract class IntegrationTestBase
{
    protected static DatabaseFixture DbFixture => TestAssemblyHooks.DbFixture;
    private readonly string _seedSqlFile;
    
    protected IntegrationTestBase(string seedSqlFile)
    {
        _seedSqlFile = seedSqlFile;
    }
    [TestInitialize]
    public async Task TestInit()
    {
        await DbFixture.TruncateDatabaseAsync();
        await DbFixture.ExecuteSqlFromFileAsync(_seedSqlFile);
    }
}
