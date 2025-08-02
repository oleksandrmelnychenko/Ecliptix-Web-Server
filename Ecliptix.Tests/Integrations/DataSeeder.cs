using System.Data;
using Microsoft.Data.SqlClient;

namespace Ecliptix.Tests.Integrations;

public class DataSeeder
{
    private const string DefaultGuid = "00000000-0000-0000-0000-000000000000";
    
    private readonly SqlConnection _connection;
    private readonly List<Func<Task>> _actions = new();

    private int _phoneId = 1;
    private Guid _phoneUniqueId;
    private Guid _deviceUniqueId;
    private Guid _verificationFlowUniqueId;
    private Guid _membershipUniqueId;

    private DataSeeder(SqlConnection connection)
    {
        _connection = connection;
    }

    public static DataSeeder Build(SqlConnection connection)
    {
        return new (connection);
    }

    public DataSeeder WithPhone(string phoneNumber, int id = 1)
    {
        _phoneId = id;
        _phoneUniqueId = Guid.NewGuid();
        
        _actions.Add(async () =>
        {
            SqlCommand cmd = new ($"""
                SET IDENTITY_INSERT PhoneNumbers ON;
                INSERT INTO PhoneNumbers (Id, PhoneNumber, Region, IsDeleted, UniqueId)
                VALUES ({id}, '{phoneNumber}', 'UA', 0, '{_phoneUniqueId}');
                SET IDENTITY_INSERT PhoneNumbers OFF;
            """, _connection);
            await cmd.ExecuteNonQueryAsync();
        });

        return this;
    }
    
    public DataSeeder WithAppDevice()
    {
        _deviceUniqueId = Guid.NewGuid();
        _actions.Add(async () =>
        {
            SqlCommand cmd = new ($"""
                INSERT INTO AppDevices (AppInstanceId, DeviceId, DeviceType, UniqueId)
                VALUES ('{DefaultGuid}', '{DefaultGuid}', 1, '{_deviceUniqueId}');
            """, _connection);
            await cmd.ExecuteNonQueryAsync();
        });

        return this;
    }
    
    public DataSeeder WithVerificationFlow()
    {
        _verificationFlowUniqueId = Guid.NewGuid();
        _actions.Add(async () =>
        {
            SqlCommand cmd = new ($"""
                                       INSERT INTO VerificationFlows(PhoneNumberId, AppDeviceId, Status, Purpose, ExpiresAt, UniqueId)
                                       VALUES (@PhoneNumberId, @AppDeviceId, 'verified', 'registration', @ExpiresAt, @UniqueId);
                                   """, _connection);
        
            cmd.Parameters.Add("@PhoneNumberId", SqlDbType.Int).Value = _phoneId;
            cmd.Parameters.Add("@AppDeviceId", SqlDbType.UniqueIdentifier).Value = _deviceUniqueId;
            cmd.Parameters.Add("@ExpiresAt", SqlDbType.DateTime2).Value = DateTime.UtcNow.AddHours(1);
            cmd.Parameters.Add("@UniqueId", SqlDbType.UniqueIdentifier).Value = _verificationFlowUniqueId;
        
            await cmd.ExecuteNonQueryAsync();
        });

        return this;
    }

    public DataSeeder WithMembership(byte[]? secureKey = null)
    {
        _membershipUniqueId = Guid.NewGuid();
        _actions.Add(async () =>
        {
            SqlCommand cmd = new ($"""
                                       INSERT INTO Memberships (
                                           PhoneNumberId, AppDeviceId, VerificationFlowId, SecureKey,
                                           Status, CreationStatus, UniqueId)
                                       VALUES (
                                           @PhoneNumberId, @AppDeviceId, @VerificationFlowId, @SecureKey,
                                           'inactive', 'otp_verified', @UniqueId);
                                   """, _connection);

            cmd.Parameters.Add("@PhoneNumberId", SqlDbType.UniqueIdentifier).Value = _phoneUniqueId;
            cmd.Parameters.Add("@AppDeviceId", SqlDbType.UniqueIdentifier).Value = _deviceUniqueId;
            cmd.Parameters.Add("@VerificationFlowId", SqlDbType.UniqueIdentifier).Value = _verificationFlowUniqueId;
            cmd.Parameters.Add("@UniqueId", SqlDbType.UniqueIdentifier).Value = _membershipUniqueId;

            if (secureKey != null)
                cmd.Parameters.Add("@SecureKey", SqlDbType.VarBinary).Value = secureKey;
            else
                cmd.Parameters.Add("@SecureKey", SqlDbType.VarBinary).Value = DBNull.Value;

            await cmd.ExecuteNonQueryAsync();
        });

        return this;
    }
    
    public async Task SeedAsync()
    {
        foreach (var action in _actions)
        {
            await action();
        }
    }
}