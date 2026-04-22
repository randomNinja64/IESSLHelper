# IESSLHelper

IESSLHelper is a Browser Helper Object (BHO) that enables HTTPS websites to work under Internet Explorer 6 on Windows XP RTM or higher.

## Requirements

- Internet Explorer 6+
- Windows XP or higher
- `curl.exe` and `curl-ca-bundle.crt` placed next to `IESSLHelper.dll` (installed automatically with the install script)

## Building

The solution file can be built in Visual Studio 2008 or higher. Note: the CURL executable and certificate bundle are not included in builds built via the solution.

## Installation

1. Close all IE browser windows.
2. Run `install.cmd` (BHO files will be placed in `%ProgramFiles%\IESSLHelper\`)

## Usage

Once installed, HTTPS sites can be navigated to in the same way as other sites within IE.

## Uninstallation

1. Run `uninstall.cmd`.

## License

IESSLHelper is licensed under the MIT License.

Third-party licenses for bundled components (`curl.exe`, `curl-ca-bundle.crt`) are located in [THIRD_PARTY_LICENSES/](THIRD_PARTY_LICENSES/).

## Credits

- cURL builds are provided by [LoRd_MuldeR](https://github.com/lordmulder).
