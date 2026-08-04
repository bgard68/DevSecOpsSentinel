C7/C8 exact package fix

This package was built from the restored files you uploaded.
It preserves every existing PackageVersion, PackageReference, and ProjectReference.

Only two additions were made:

Directory.Packages.props:
  <PackageVersion Include="Microsoft.Extensions.Http" Version="10.0.10" />

src/DevSecOpsSentinel.Infrastructure/DevSecOpsSentinel.Infrastructure.csproj:
  <PackageReference Include="Microsoft.Extensions.Http" />

Extract over C:\DevSecOpsSentinel, then run:

dotnet restore .\DevSecOpsSentinel.slnx
dotnet build .\DevSecOpsSentinel.slnx --configuration Release
dotnet test .\DevSecOpsSentinel.slnx --configuration Release --no-build
