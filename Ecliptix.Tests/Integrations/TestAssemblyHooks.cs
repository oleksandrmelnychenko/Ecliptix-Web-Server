namespace Ecliptix.Tests.Integrations;

[TestClass]
public class TestAssemblyHooks
{
    public static DatabaseFixture DbFixture;

    [AssemblyInitialize]
    public static async Task AssemblyInit(TestContext context)
    {
        DbFixture = new DatabaseFixture();
        await DbFixture.InitializeAsync();
    }

    [AssemblyCleanup]
    public static async Task AssemblyCleanup()
    {
        await DbFixture.DisposeAsync();
    }
}
