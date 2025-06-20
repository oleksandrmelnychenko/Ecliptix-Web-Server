using System.Collections.Concurrent;

namespace Ecliptix.Core.AuthenticationSystem;

public class MockUserRepository
{
    private readonly ConcurrentDictionary<string, UserOpaqueRecord> _users = new();

    public Task<UserOpaqueRecord?> GetUserByUsernameAsync(string username)
    {
        _users.TryGetValue(username, out var user);
        return Task.FromResult(user);
    }

    public Task StoreUserAsync(UserOpaqueRecord userProfile)
    {
        _users[userProfile.Username] = userProfile;
        return Task.CompletedTask;
    }
}