# Context layout

- IdentityAccess: membership/account persistence lives under `Contexts/IdentityAccess/Infrastructure/Persistors` (EF compiled queries, Akka persistors).
- DeviceProvisioning: app device persistence lives under `Contexts/DeviceProvisioning/Infrastructure/Persistors`.

Persistors were moved out of `Memberships/Persistors` and `AppDevices/Persistors` to make navigation context-first. Namespaces stay the same to avoid code breakage; adjust any hardcoded paths if you had them.
