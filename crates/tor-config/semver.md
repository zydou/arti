ADDED: ReconfigureError::Bug enum variant
ADDED: misc::PaddingLevel
ADDED: resolve_option_general
ADDED: sources::FoundConfigFiles
BREAKING: ConfigurationSources takes ConfigurationSource for files, not Paths
BREAKING: ConfigurationSources::from_cmdline wants an iterator of defaults
BREAKING: load::resolve_ignore_unrecognized renamed resolve_ignore_warnings
BREAKING: load::resolve_return_unrecognized replaced with resolve_return_results
BREAKING: load::UnrecognizedKey renamed to DisfavouredKey
ADDED: Support for tracking deprecated config keys
