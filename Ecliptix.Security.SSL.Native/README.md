# Ecliptix.Security.SSL.Native

C# server library for ASP.NET Core applications providing cryptographic operations with private keys.

## Features

- **RSA Encryption/Decryption**: Encrypt with client public keys, decrypt with server private key
- **Ed25519 Digital Signatures**: Create digital signatures using server's private key
- **Embedded Private Keys**: Private keys stored as embedded resources in the library
- **Cross-Platform**: Works on Windows, macOS, and Linux

## Usage

```csharp
using Ecliptix.Security.SSL.Native.Services;

// Initialize the service
using var serverService = new ServerSecurityService();
var initResult = await serverService.InitializeAsync();

if (initResult.IsError)
{
    Console.WriteLine($"Initialization failed: {initResult.Error}");
    return;
}

// Sign a message with Ed25519
string message = "Hello, World!";
byte[] messageBytes = Encoding.UTF8.GetBytes(message);
var signResult = await serverService.SignEd25519Async(messageBytes);

if (signResult.IsSuccess)
{
    byte[] signature = signResult.Value;
    // Send signature to client for verification
}

// Decrypt RSA ciphertext from client
var decryptResult = await serverService.DecryptRsaAsync(ciphertext);
if (decryptResult.IsSuccess)
{
    byte[] plaintext = decryptResult.Value;
    string message = Encoding.UTF8.GetString(plaintext);
}
```

## Architecture

### Security Model
- **Private keys** are embedded in the server library as resources
- **Client library** can only encrypt and verify (no private keys)
- **Server library** can decrypt and sign (has private keys)

### Files Structure
```
Ecliptix.Security.SSL.Native/
├── Native/                          # P/Invoke wrappers
│   ├── EcliptixServerNativeLibrary.cs
│   ├── EcliptixServerResult.cs
│   └── EcliptixServerConstants.cs
├── Services/                        # High-level C# API
│   └── ServerSecurityService.cs
├── Resources/                       # Embedded private keys
│   ├── EmbeddedResourceLoader.cs
│   ├── ed25519_private.txt
│   └── rsa_server_private.txt
├── Failures/                       # Error handling
│   ├── ServerSecurityFailure.cs
│   └── ServerSecurityFailureType.cs
├── Common/                         # Utilities
│   └── Result.cs
└── libecliptix_server_security.dylib # Native library
```

## API Reference

### ServerSecurityService

#### Methods

- `InitializeAsync()` - Initialize the native library and load private keys
- `EncryptRsaAsync(plaintext, publicKeyPem)` - Encrypt data using client's public key
- `DecryptRsaAsync(ciphertext)` - Decrypt data using server's private key
- `SignEd25519Async(message)` - Create Ed25519 signature using server's private key

#### Error Handling

All methods return `Result<T, ServerSecurityFailure>`:
- `result.IsSuccess` - Check if operation succeeded
- `result.Value` - Get the result value (only if successful)
- `result.Error` - Get the error details (only if failed)

## Deployment

### Development (macOS)
The library automatically loads the `.dylib` file from the application directory.

### Production (Linux)
- Copy `libecliptix_server_security.so` to the deployment directory
- Ensure the native library is in the `LD_LIBRARY_PATH` or same directory as the executable

### ASP.NET Core Integration

```csharp
// In Program.cs
services.AddSingleton<ServerSecurityService>();

// In your controller
[ApiController]
public class CryptoController : ControllerBase
{
    private readonly ServerSecurityService _securityService;

    public CryptoController(ServerSecurityService securityService)
    {
        _securityService = securityService;
    }

    [HttpPost("sign")]
    public async Task<IActionResult> SignMessage([FromBody] string message)
    {
        var messageBytes = Encoding.UTF8.GetBytes(message);
        var result = await _securityService.SignEd25519Async(messageBytes);

        return result.IsSuccess
            ? Ok(new { signature = Convert.ToBase64String(result.Value) })
            : BadRequest(result.Error.Message);
    }
}
```

## Testing

Run the test program:
```bash
dotnet run
```

Expected output:
```
✅ Server security service initialized successfully
✅ Ed25519 signing successful! Signature: [base64-signature]
✅ RSA decryption capability ready
✅ C# Server Security Library test completed!
```