# Preferences headers

These headers come from the open-source [theos/headers](https://github.com/theos/headers)
repository (`Preferences/` directory). They are used only as compile-time
declarations for the private `Preferences.framework` API; the built bundle does
not link a copy and resolves the classes from the host Settings process at
runtime with `-undefined dynamic_lookup`.
