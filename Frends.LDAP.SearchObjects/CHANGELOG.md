# Changelog

## [2.0.0] - 2024-11-06
### Added
- [Breaking] Parameter for AnonymousBind to enable to connect without credentials.
- [Breaking] Parameter for LDAPProtocolVersion to choose what LDAP version should be used.
- Check for Filter parameter that it's not empty and set null to it if it is so that the library sets objectClass=* as the filter.

## [1.0.0] - 2022-10-03
### Added
- Initial implementation