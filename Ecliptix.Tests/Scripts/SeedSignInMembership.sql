SET IDENTITY_INSERT PhoneNumbers ON;

INSERT INTO PhoneNumbers (
    Id,
    PhoneNumber,
    Region,
    IsDeleted,
    UniqueId
)
VALUES
    (1,'+380500000001', 'UA', 0, '00000000-0000-0000-0000-000000000001'),
    (2,'+380500000002', 'UA', 0, '00000000-0000-0000-0000-000000000002');
;

SET IDENTITY_INSERT PhoneNumbers OFF;

-------------------------------------

INSERT INTO AppDevices (
    AppInstanceId,
    DeviceId,
    DeviceType,
    UniqueId
)
VALUES 
    ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002', 1, '00000000-0000-0000-0000-000000000002');

-------------------------------------
    
INSERT INTO VerificationFlows (
    PhoneNumberId,
    AppDeviceId,
    Status,
    Purpose,
    ExpiresAt,
    UniqueId
)
VALUES 
    (2, '00000000-0000-0000-0000-000000000002', 'verified', 'registration', '2025-07-25 09:51:33.7400000', '00000000-0000-0000-0000-000000000002');

-------------------------------------

INSERT INTO Memberships  ( 
    PhoneNumberId,
    AppDeviceId,
    VerificationFlowId,
    SecureKey,
    Status,
    CreationStatus,
    UniqueId
                          
)
VALUES 
    ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002',null,'inactive','otp_verified','00000000-0000-0000-0000-000000000002');

------------------------------------

