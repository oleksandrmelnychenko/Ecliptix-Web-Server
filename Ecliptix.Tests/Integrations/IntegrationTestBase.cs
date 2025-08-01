namespace Ecliptix.Tests.Integrations;

public abstract class IntegrationTestBase
{
    protected static DatabaseFixture DbFixture => TestAssemblyHooks.DbFixture;

    [TestInitialize]
    public async Task TestInit()
    {
        await DbFixture.TruncateDatabaseAsync();
        await DbFixture.SeedDatabaseAsync();
    }
}
